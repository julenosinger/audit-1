// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer client adapter (Phase 5B)
//
// Thin adapter over the official genlayer-js SDK (bundled into
// public/genlayer-sdk.bundle.js and exposed as window.GenLayerSDK).
//
// It exposes a small API so the rest of the app never touches SDK internals:
//   initializeGenLayer / isGenLayerAvailable / getGenLayerNetwork
//   getReadClient / getContractSchema / read / getAnalysis
//   analyzeEvidence(payload, opts)  — full write → wait → read lifecycle
//
// No private key, no secret, no external AI. Writes require a wallet account
// (opts.account) provided by the caller; reads work without a wallet.
//
// Unit-testable: createAdapter(mockSDK) lets tests inject a fake transport.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerClient = api;
})(function () {
  'use strict';

  var NETWORK = { name: 'Bradbury', chainId: 4221, rpc: 'https://rpc-bradbury.genlayer.com' };
  var CONTRACT_KEY = 'auditai.genlayer.contract';

  function getSdk() {
    return (typeof window !== 'undefined' && window.GenLayerSDK) ||
      (typeof globalThis !== 'undefined' && globalThis.GenLayerSDK);
  }

  function getStoredContract() {
    try { return localStorage.getItem(CONTRACT_KEY) || ''; } catch (e) { return ''; }
  }

  // Map a raw SDK/wallet error to a canonical, UI-facing error code. Kept at
  // module scope so it is unit-testable without a live chain.
  function toErrorCode(e) {
    var m = String((e && e.message) || e || '');
    var name = String((e && e.name) || '');
    var code = e && e.code;
    if (name === 'UserRejectedRequestError' || code === 4001 ||
        /user rejected|rejected the (request|transaction)|denied transaction|permission denied/i.test(m)) return 'USER_REJECTED';
    if (/wrong network|wallet is on chain|chain mismatch|addchain|switch.{0,20}chain/i.test(m)) return 'WRONG_NETWORK';
    if (/insufficient funds|insufficient balance|not enough funds|gas required exceeds/i.test(m)) return 'INSUFFICIENT_BALANCE';
    if (/timed out|timeout/i.test(m)) return 'TRANSACTION_TIMEOUT';
    if (/revert|out of gas|invalid opcode/i.test(m)) return 'TRANSACTION_FAILED';
    if (/econnrefused|enotfound|unreachable|failed to fetch|fetch failed|network error/i.test(m)) return 'GENLAYER_NETWORK_UNAVAILABLE';
    return 'GENLAYER_ERROR';
  }

  function createAdapter(SDK) {
    var sdk = SDK || getSdk();
    var readClient = null;

    function available() {
      return !!(sdk && typeof sdk.createClient === 'function' && sdk.chains && sdk.chains.testnetBradbury);
    }

    function ensureRead() {
      if (readClient) return readClient;
      if (!available()) return null;
      try { readClient = sdk.createClient({ chain: sdk.chains.testnetBradbury }); }
      catch (e) { readClient = null; }
      return readClient;
    }

    function isAvailable() { return available(); }
    function getNetwork() { return NETWORK; }
    function getReadClient() { return ensureRead(); }

    async function getContractSchema(address) {
      var c = ensureRead();
      if (!c) throw new Error('SDK_UNAVAILABLE');
      return c.getContractSchema(address);
    }

    async function read(address, functionName, args) {
      var c = ensureRead();
      if (!c) throw new Error('SDK_UNAVAILABLE');
      return c.readContract({ address: address, functionName: functionName, args: args || [], jsonSafeReturn: true });
    }

    async function getAnalysis(auditorAddr, contractAddr) {
      return read(auditorAddr, 'get_analysis', [contractAddr]);
    }

    function emit(opts, state, detail) {
      if (opts && typeof opts.onStatus === 'function') {
        try { opts.onStatus(state, detail); } catch (e) {}
      }
    }

    // Full lifecycle: verify schema → write analyze_evidence → wait receipt →
    // read get_analysis → parse JSON. Returns the parsed response object, or
    // throws a descriptive Error (caught by the auditor as a FAILED status).
    // Emits onStatus(state, detail) so the UI can render the real progress.
    async function analyzeEvidence(payload, opts) {
      opts = opts || {};
      emit(opts, 'PREPARING');
      if (!available()) throw new Error('SDK_UNAVAILABLE');
      var auditorAddr = opts.contractAddress || getStoredContract();
      if (!auditorAddr) throw new Error('GENLAYER_AUDITOR_NOT_DEPLOYED');

      emit(opts, 'CONNECTING', { contract: auditorAddr });
      var c = ensureRead();
      var sch;
      try { sch = await c.getContractSchema(auditorAddr); }
      catch (e) {
        throw new Error(toErrorCode(e) === 'GENLAYER_NETWORK_UNAVAILABLE' ? 'GENLAYER_NETWORK_UNAVAILABLE' : 'CONTRACT_UNAVAILABLE');
      }
      if (!sch || !sch.methods) throw new Error('SCHEMA_UNAVAILABLE');
      if (!sch.methods['analyze_evidence']) throw new Error('METHOD_MISSING: analyze_evidence');
      if (!sch.methods['get_analysis']) throw new Error('METHOD_MISSING: get_analysis');

      var account = opts.account;
      emit(opts, 'WAITING_WALLET');
      if (!account) throw new Error('WALLET_REQUIRED');

      var wc;
      try { wc = sdk.createClient({ chain: sdk.chains.testnetBradbury, account: account }); }
      catch (e) { throw new Error(toErrorCode(e)); }

      var evidenceJson = JSON.stringify(payload);
      var tx;
      try {
        tx = await wc.writeContract({
          address: auditorAddr,
          functionName: 'analyze_evidence',
          args: [payload.contract.address, evidenceJson],
          value: BigInt(0)
        });
      } catch (e) { throw new Error(toErrorCode(e)); }

      var hash = (tx && typeof tx === 'object' && tx.hash !== undefined) ? tx.hash : (typeof tx === 'string' ? tx : null);
      if (!hash) throw new Error('NO_TX_HASH');

      emit(opts, 'SUBMITTED', hash);

      try {
        var receipt = await wc.waitForTransactionReceipt({
          hash: hash,
          status: 'FINALIZED',
          interval: (opts.interval || 2000),
          retries: (opts.retries || 90)
        });
        if (receipt && receipt.status === 'FAILED') throw new Error('TRANSACTION_FAILED');
      } catch (e) {
        if (e && e.message === 'TRANSACTION_FAILED') throw e;
        throw new Error(toErrorCode(e));
      }

      emit(opts, 'FINALIZING', hash);

      var res;
      try {
        res = await c.readContract({ address: auditorAddr, functionName: 'get_analysis', args: [payload.contract.address], jsonSafeReturn: true });
      } catch (e) {
        throw new Error(toErrorCode(e) === 'GENLAYER_NETWORK_UNAVAILABLE' ? 'GENLAYER_NETWORK_UNAVAILABLE' : 'GENLAYER_ERROR');
      }

      emit(opts, 'RETRIEVING', hash);

      var text = (typeof res === 'string') ? res : JSON.stringify(res);
      if (!text || text === 'NO_ANALYSIS') throw new Error('NO_RESULT');

      var parsed;
      try { parsed = JSON.parse(text); }
      catch (e) { throw new Error('INVALID_RESULT_JSON'); }

      emit(opts, 'COMPLETE', parsed);
      return parsed;
    }

    return {
      NETWORK: NETWORK,
      isAvailable: isAvailable,
      getNetwork: getNetwork,
      getReadClient: getReadClient,
      getContractSchema: getContractSchema,
      read: read,
      getAnalysis: getAnalysis,
      analyzeEvidence: analyzeEvidence
    };
  }

  return { createAdapter: createAdapter, getSdk: getSdk, toErrorCode: toErrorCode, NETWORK: NETWORK, CONTRACT_KEY: CONTRACT_KEY };
});
