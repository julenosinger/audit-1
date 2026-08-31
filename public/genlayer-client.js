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

    // Full lifecycle: verify schema → write analyze_evidence → wait receipt →
    // read get_analysis → parse JSON. Returns the parsed response object, or
    // throws a descriptive Error (caught by the auditor as a FAILED status).
    async function analyzeEvidence(payload, opts) {
      opts = opts || {};
      if (!available()) throw new Error('SDK_UNAVAILABLE');
      var auditorAddr = opts.contractAddress || getStoredContract();
      if (!auditorAddr) throw new Error('NO_CONTRACT');

      var c = ensureRead();
      var sch;
      try { sch = await c.getContractSchema(auditorAddr); }
      catch (e) { throw new Error('CONTRACT_UNAVAILABLE'); }
      if (!sch || !sch.methods) throw new Error('SCHEMA_UNAVAILABLE');
      if (!sch.methods['analyze_evidence']) throw new Error('METHOD_MISSING: analyze_evidence');
      if (!sch.methods['get_analysis']) throw new Error('METHOD_MISSING: get_analysis');

      var account = opts.account;
      if (!account) throw new Error('WALLET_REQUIRED');

      var wc = sdk.createClient({ chain: sdk.chains.testnetBradbury, account: account });
      var evidenceJson = JSON.stringify(payload);
      var tx = await wc.writeContract({
        address: auditorAddr,
        functionName: 'analyze_evidence',
        args: [payload.contract.address, evidenceJson],
        value: BigInt(0)
      });
      var hash = (tx && typeof tx === 'object' && tx.hash !== undefined) ? tx.hash : (typeof tx === 'string' ? tx : null);
      if (!hash) throw new Error('NO_TX_HASH');

      await wc.waitForTransactionReceipt({
        hash: hash,
        status: 'FINALIZED',
        interval: (opts.interval || 2000),
        retries: (opts.retries || 90)
      });

      var res = await c.readContract({ address: auditorAddr, functionName: 'get_analysis', args: [payload.contract.address], jsonSafeReturn: true });
      var text = (typeof res === 'string') ? res : JSON.stringify(res);
      if (!text || text === 'NO_ANALYSIS') throw new Error('NO_RESULT');

      var parsed;
      try { parsed = JSON.parse(text); }
      catch (e) { throw new Error('INVALID_RESULT_JSON'); }
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

  return { createAdapter: createAdapter, getSdk: getSdk, NETWORK: NETWORK, CONTRACT_KEY: CONTRACT_KEY };
});
