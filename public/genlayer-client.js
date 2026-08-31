// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer client adapter (Phase 5B.3, multi-network)
//
// Thin adapter over the official genlayer-js SDK (bundled into
// public/genlayer-sdk.bundle.js and exposed as window.GenLayerSDK).
//
// Multi-network: each GenLayer network is paired with its AuditAI contract in
// the NETWORKS registry below (single source of truth). A network is only
// usable when `deployed` is true AND `contract` is set. The selected network's
// chain and contract are always used together — never cross-paired.
//
// API:
//   createAdapter(SDK?, { networkId, networks })  → adapter instance
//   adapter.preflight()      — capability check (no transaction)
//   adapter.analyzeEvidence(payload, opts) — full write → wait → read lifecycle
//
// No private key, no secret, no external AI. Writes require a wallet account
// (opts.account); reads work without a wallet.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerClient = api;
})(function () {
  'use strict';

  // ── Network registry (single source of truth) ──────────────────────────────
  // Each entry pairs a network with its AuditAI contract. Studionet is the
  // confirmed deployment; Bradbury is NOT yet deployed (contract must be set
  // only after it has been verified on chain 4221).
  var NETWORKS = {
    studionet: { id: 'studionet', name: 'Studionet', chainId: 61999, rpc: 'https://studio.genlayer.com/api', contract: '0xF2c549Bf2Dc106a28354B1444298DD460601856B', deployed: true },
    bradbury:  { id: 'bradbury',  name: 'Bradbury',  chainId: 4221,  rpc: 'https://rpc-bradbury.genlayer.com', contract: '', deployed: false }
  };
  var DEFAULT_NETWORK_ID = 'studionet';
  // SDK chain object key per network id (genlayer-js exposes studionet /
  // testnetBradbury, etc).
  var SDK_CHAIN_KEY = { studionet: 'studionet', bradbury: 'testnetBradbury' };

  function getSdk() {
    return (typeof window !== 'undefined' && window.GenLayerSDK) ||
      (typeof globalThis !== 'undefined' && globalThis.GenLayerSDK);
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

  function createAdapter(SDK, opts) {
    opts = opts || {};
    var sdk = SDK || getSdk();
    var networks = opts.networks || NETWORKS;
    var networkId = (opts.networkId && networks[opts.networkId]) ? opts.networkId : DEFAULT_NETWORK_ID;
    var readClient = null;

    function network() { return networks[networkId] || null; }

    function sdkChain() {
      if (!sdk || !sdk.chains) return null;
      var key = SDK_CHAIN_KEY[networkId];
      return key ? (sdk.chains[key] || null) : null;
    }

    function available() {
      return !!(sdk && typeof sdk.createClient === 'function' && sdkChain());
    }

    function ensureRead() {
      if (readClient) return readClient;
      if (!available()) return null;
      try { readClient = sdk.createClient({ chain: sdkChain() }); }
      catch (e) { readClient = null; }
      return readClient;
    }

    function isAvailable() { return available(); }
    function getNetwork() { return network(); }
    function getNetworkId() { return networkId; }
    function getContract() { var n = network(); return n ? n.contract : ''; }
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

    // Pre-flight capability check for the selected network. Performs a real
    // schema read but submits NO transaction.
    async function preflight(overrideContract) {
      if (!available()) return { ok: false, error: 'SDK_UNAVAILABLE' };
      var n = network();
      if (!n) return { ok: false, error: 'UNKNOWN_NETWORK' };
      var contract = overrideContract || n.contract;
      if (!n.deployed || !contract) return { ok: false, error: 'GENLAYER_AUDITOR_NOT_DEPLOYED', network: n };
      var c = ensureRead();
      if (!c) return { ok: false, error: 'SDK_UNAVAILABLE', network: n };
      var sch;
      try { sch = await c.getContractSchema(contract); }
      catch (e) { return { ok: false, error: 'CONTRACT_UNAVAILABLE', network: n }; }
      if (!sch || !sch.methods) return { ok: false, error: 'SCHEMA_UNAVAILABLE', network: n };
      if (!sch.methods['analyze_evidence']) return { ok: false, error: 'METHOD_MISSING: analyze_evidence', network: n };
      if (!sch.methods['get_analysis']) return { ok: false, error: 'METHOD_MISSING: get_analysis', network: n };
      return { ok: true, network: n, contract: contract, methods: Object.keys(sch.methods) };
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
      var n = network();
      if (!n) throw new Error('UNKNOWN_NETWORK');
      if (!n.deployed) throw new Error('GENLAYER_AUDITOR_NOT_DEPLOYED');
      var auditorAddr = opts.contractAddress || n.contract;
      if (!auditorAddr) throw new Error('GENLAYER_AUDITOR_NOT_DEPLOYED');
      // Pairing guard: an explicit override must belong to the selected network.
      if (opts.contractAddress && n.contract && String(opts.contractAddress).toLowerCase() !== String(n.contract).toLowerCase()) {
        throw new Error('NETWORK_CONTRACT_MISMATCH');
      }

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
      try { wc = sdk.createClient({ chain: sdkChain(), account: account }); }
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
      isAvailable: isAvailable,
      getNetwork: getNetwork,
      getNetworkId: getNetworkId,
      getContract: getContract,
      getReadClient: getReadClient,
      getContractSchema: getContractSchema,
      read: read,
      getAnalysis: getAnalysis,
      preflight: preflight,
      analyzeEvidence: analyzeEvidence
    };
  }

  return {
    createAdapter: createAdapter,
    getSdk: getSdk,
    toErrorCode: toErrorCode,
    NETWORKS: NETWORKS,
    DEFAULT_NETWORK_ID: DEFAULT_NETWORK_ID,
    SDK_CHAIN_KEY: SDK_CHAIN_KEY
  };
});
