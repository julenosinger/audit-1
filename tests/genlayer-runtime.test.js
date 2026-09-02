'use strict';
// Phase 5B.3 tests: multi-network GenLayer client adapter (real SDK shape,
// mocked transport). Only the transport is mocked — never a fake result.
// Run with:  node tests/genlayer-runtime.test.js
const test = require('node:test');
const assert = require('node:assert');
const GenLayerClient = require('../public/genlayer-client.js');
const Auditor = require('../public/genlayer-auditor.js');
const Engine = require('../public/audit-engine.js');
require('../public/genlayer-tx.js');

const TEST_NETWORKS = {
  studionet: { id: 'studionet', name: 'Studionet', chainId: 61999, rpc: 'https://studio.genlayer.com/api', contract: '0x' + 'ab'.repeat(20), deployed: true },
  bradbury:  { id: 'bradbury',  name: 'Bradbury Testnet',  chainId: 4221,  rpc: 'https://rpc-bradbury.genlayer.com', contract: '0x' + 'cd'.repeat(20), deployed: true }
};
const STUDIO_CONTRACT = TEST_NETWORKS.studionet.contract;
const BRADBURY_CONTRACT = TEST_NETWORKS.bradbury.contract;

// A fixture where Bradbury has NOT deployed an auditor (exercises the honest
// GENLAYER_AUDITOR_NOT_DEPLOYED guard without touching the real registry).
const UNDEPLOYED_NETWORKS = {
  studionet: TEST_NETWORKS.studionet,
  bradbury: { id: 'bradbury', name: 'Bradbury Testnet', chainId: 4221, rpc: 'https://rpc-bradbury.genlayer.com', contract: '', deployed: false }
};

function mockSdk() {
  var readClient = {
    getContractSchema: async function () {
      return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {}, publish_audit: {} } };
    },
    getTransaction: async function () {
      return { statusName: 'FINALIZED', status: 7, txExecutionResultName: 'FINISHED_WITH_RETURN' };
    },
    readContract: async function (args) {
      if (args.functionName === 'get_analysis') {
        return '{"verdict":"NO_CONFIRMED_VULNERABILITY","confidence":"HIGH","findings":[],"globalAssessment":{"riskLevel":"LOW RISK","confidence":"HIGH","limitations":["linear disassembly"]}}';
      }
      return '';
    }
  };
  var writeClient = {
    writeContract: async function () { return { hash: '0xabc123' }; },
    waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
  };
  return {
    createClient: function (config) { return config && config.account ? writeClient : readClient; },
    chains: {
      studionet: { id: 61999, name: 'Studionet' },
      testnetBradbury: { id: 4221, name: 'Bradbury' }
    }
  };
}

function makeAdapter(sdk, netId) {
  return GenLayerClient.createAdapter(sdk || mockSdk(), { networkId: netId || 'studionet', networks: TEST_NETWORKS });
}

// ── network registry / pairing ──────────────────────────────────────────────

test('registry: Studionet + Bradbury both deployed with AuditAI contracts', function () {
  var reg = GenLayerClient.NETWORKS;
  assert.equal(reg.studionet.deployed, true);
  assert.match(reg.studionet.contract, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(reg.bradbury.deployed, true);
  assert.equal(reg.bradbury.contract.toLowerCase(), '0x119ac58af8546df0b0e55eb24277c756d9458000');
  assert.equal(reg.bradbury.chainId, 4221);
  assert.equal(reg.bradbury.knownContract.toLowerCase(), '0x119ac58af8546df0b0e55eb24277c756d9458000');
});

test('studionet selects the studionet contract', function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  assert.equal(a.getNetworkId(), 'studionet');
  assert.equal(a.getNetwork().chainId, 61999);
  assert.equal(a.getContract(), STUDIO_CONTRACT);
  assert.equal(a.isAvailable(), true);
});

test('bradbury selects the bradbury config (AuditAI deployed on 4221)', function () {
  var a = makeAdapter(mockSdk(), 'bradbury');
  assert.equal(a.getNetworkId(), 'bradbury');
  assert.equal(a.getNetwork().chainId, 4221);
  assert.equal(a.getNetwork().deployed, true);
  assert.equal(a.getContract(), BRADBURY_CONTRACT);
});

test('contract schema exposes analyze_evidence and get_analysis', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var sch = await a.getContractSchema(STUDIO_CONTRACT);
  assert.ok(sch.methods['analyze_evidence']);
  assert.ok(sch.methods['get_analysis']);
});

// ── lifecycle ────────────────────────────────────────────────────────────────

test('analyzeEvidence: full write → wait → read lifecycle returns parsed result', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  var resp = await a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  assert.equal(resp.verdict, 'NO_CONFIRMED_VULNERABILITY');
});

test('analyzeEvidence: no account => WALLET_REQUIRED', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, {});
  }, /WALLET_REQUIRED/);
});

test('analyzeEvidence: undeployed auditor => GENLAYER_AUDITOR_NOT_DEPLOYED', async function () {
  var a = GenLayerClient.createAdapter(mockSdk(), { networkId: 'bradbury', networks: UNDEPLOYED_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  }, /GENLAYER_AUDITOR_NOT_DEPLOYED/);
});

test('analyzeEvidence: network/contract mismatch => NETWORK_CONTRACT_MISMATCH', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'cd'.repeat(20), account: '0x' + '11'.repeat(20) });
  }, /NETWORK_CONTRACT_MISMATCH/);
});

test('analyzeEvidence: missing method => METHOD_MISSING', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    return {
      getContractSchema: async function () { return { ctor: {}, methods: {} }; }
    };
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  }, /METHOD_MISSING/);
});

test('analyzeEvidence: FINALIZED + NO_ANALYSIS => AUDIT_RESULT_PENDING (accepted, recovering)', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = {
      getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
      getTransaction: async function () { return { statusName: 'FINALIZED', status: 7, txExecutionResultName: 'FINISHED_WITH_RETURN' }; },
      readContract: async function () { return 'NO_ANALYSIS'; }
    };
    var write = { writeContract: async function () { return { hash: '0xabc123' }; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20), recoveryRetries: 1 });
  }, /AUDIT_RESULT_PENDING/);
});

// ── preflight ────────────────────────────────────────────────────────────────

test('preflight: studionet passes and reports methods', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var pf = await a.preflight();
  assert.equal(pf.ok, true);
  assert.equal(pf.contract, STUDIO_CONTRACT);
  assert.ok(pf.methods.indexOf('analyze_evidence') !== -1);
  assert.ok(pf.methods.indexOf('get_analysis') !== -1);
});

test('preflight: undeployed auditor reports GENLAYER_AUDITOR_NOT_DEPLOYED', async function () {
  var a = GenLayerClient.createAdapter(mockSdk(), { networkId: 'bradbury', networks: UNDEPLOYED_NETWORKS });
  var pf = await a.preflight();
  assert.equal(pf.ok, false);
  assert.equal(pf.error, 'GENLAYER_AUDITOR_NOT_DEPLOYED');
});

// ── error mapping / progress ─────────────────────────────────────────────────

test('toErrorCode maps wallet/network/transaction errors to canonical codes', function () {
  var f = GenLayerClient.toErrorCode;
  assert.equal(f({ code: 4001 }), 'USER_REJECTED');
  assert.equal(f({ name: 'UserRejectedRequestError', message: 'User rejected the request' }), 'USER_REJECTED');
  assert.equal(f(new Error('Wallet is on chain 1 but client is on chain 4221')), 'WRONG_NETWORK');
  assert.equal(f(new Error('insufficient funds for gas')), 'INSUFFICIENT_BALANCE');
  assert.equal(f(new Error('Timed out waiting for transaction')), 'TRANSACTION_TIMEOUT');
  assert.equal(f(new Error('execution reverted')), 'TRANSACTION_FAILED');
  assert.equal(f(new Error('fetch failed')), 'GENLAYER_NETWORK_UNAVAILABLE');
  assert.equal(f(new Error('something else entirely')), 'GENLAYER_ERROR');
});

test('analyzeEvidence emits onStatus lifecycle and surfaces the real tx hash', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  var states = [];
  var txHash = null;
  await a.analyzeEvidence(payload, {
    account: '0x' + '11'.repeat(20),
    onStatus: function (s, d) { states.push(s); if (s === 'SUBMITTED') txHash = d; }
  });
  assert.deepEqual(states, ['PREPARING', 'CONNECTING', 'WAITING_WALLET', 'SUBMITTED', 'FINALIZED', 'RETRIEVING', 'RAW_RESULT', 'COMPLETE']);
  assert.equal(txHash, '0xabc123');
});

test('analyzeEvidence: wallet rejection on write => USER_REJECTED', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = { getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; }, readContract: async function () { return '{}'; } };
    var write = {
      writeContract: async function () { var e = new Error('User rejected the request'); e.code = 4001; throw e; },
      waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
    };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  }, /USER_REJECTED/);
});

test('analyzeEvidence: RPC failure during status polling => GENLAYER_NETWORK_UNAVAILABLE', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = {
      getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
      getTransaction: async function () { throw new Error('fetch failed'); },
      readContract: async function () { return '{}'; }
    };
    var write = { writeContract: async function () { return { hash: '0xabc123' }; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20), pollInterval: 1, maxConsecutiveRpcErrors: 2 });
  }, /GENLAYER_NETWORK_UNAVAILABLE/);
});

test('analyzeEvidence: transaction FINISHED_WITH_ERROR => TRANSACTION_FAILED', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = {
      getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
      getTransaction: async function () { return { statusName: 'FINALIZED', status: 7, txExecutionResultName: 'FINISHED_WITH_ERROR' }; },
      readContract: async function () { return '{}'; }
    };
    var write = { writeContract: async function () { return { hash: '0xabc123' }; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  }, /TRANSACTION_FAILED/);
});

test('analyzeEvidence: transaction CANCELED => TRANSACTION_CANCELED', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = {
      getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
      getTransaction: async function () { return { statusName: 'CANCELED', status: 8 }; },
      readContract: async function () { return '{}'; }
    };
    var write = { writeContract: async function () { return { hash: '0xabc123' }; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  }, /TRANSACTION_CANCELED/);
});

// ── auditor integration ──────────────────────────────────────────────────────

test('auditor integration: adapter + valid response => FINALIZED', async function () {
  var adapter = makeAdapter(mockSdk(), 'studionet');
  var local = Engine.analyze('600054f16000600155');
  var res = await Auditor.analyze(adapter, local, { account: '0x' + '11'.repeat(20), timeoutMs: 2000 });
  assert.equal(res.status, 'FINALIZED');
  assert.ok(res.genlayer);
});

test('auditor integration: adapter without account => FAILED (local preserved)', async function () {
  var adapter = makeAdapter(mockSdk(), 'studionet');
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(adapter, local, { timeoutMs: 2000 });
  assert.equal(res.status, 'FAILED');
  assert.equal(res.local, local);
  assert.equal(res.genlayer, null);
});

test('auditor: emits VALIDATING/VALIDATED and surfaces error code', async function () {
  var adapter = makeAdapter(mockSdk(), 'studionet');
  var local = Engine.analyze('f1');
  var states = [];
  var res = await Auditor.analyze(adapter, local, { account: '0x' + '11'.repeat(20), timeoutMs: 2000, onStatus: function (s) { states.push(s); } });
  assert.equal(res.status, 'FINALIZED');
  assert.ok(states.indexOf('VALIDATING') !== -1);
  assert.ok(states.indexOf('VALIDATED') !== -1);
});

test('auditor: no account surfaces WALLET_REQUIRED code via FAILED', async function () {
  var adapter = makeAdapter(mockSdk(), 'studionet');
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(adapter, local, { timeoutMs: 2000 });
  assert.equal(res.status, 'FAILED');
  assert.equal(res.error, 'WALLET_REQUIRED');
});

test('unavailable SDK => isAvailable false', function () {
  var a = GenLayerClient.createAdapter({}, { networkId: 'studionet', networks: TEST_NETWORKS });
  assert.equal(a.isAvailable(), false);
});

// ── result normalization / parsing ───────────────────────────────────────────

test('normalize: object passthrough (JSON.parse never called on an object)', function () {
  var obj = { verdict: 'NO_CONFIRMED_VULNERABILITY', confidence: 'HIGH', findings: [] };
  var n = GenLayerClient.normalizeGenLayerResult(obj);
  assert.equal(n.ok, true);
  assert.equal(n.value, obj);
  assert.equal(n.parsed, false);
});

test('normalize: serialized JSON string is parsed once', function () {
  var n = GenLayerClient.normalizeGenLayerResult('{"verdict":"NEEDS_REVIEW","confidence":"LOW","findings":[]}');
  assert.equal(n.ok, true);
  assert.equal(n.parsed, true);
  assert.equal(n.value.verdict, 'NEEDS_REVIEW');
});

test('normalize: JSON with trailing commas is cleaned and parsed', function () {
  var n = GenLayerClient.normalizeGenLayerResult('{"verdict":"NEEDS_REVIEW","confidence":"LOW","findings":[],}');
  assert.equal(n.ok, true);
  assert.equal(n.value.verdict, 'NEEDS_REVIEW');
});

test('normalize: markdown-fenced JSON is parsed', function () {
  var n = GenLayerClient.normalizeGenLayerResult('```json\n{"verdict":"NEEDS_REVIEW","confidence":"LOW","findings":[]}\n```');
  assert.equal(n.ok, true);
  assert.equal(n.value.verdict, 'NEEDS_REVIEW');
});

test('normalize: JSON wrapped in prose is extracted', function () {
  var n = GenLayerClient.normalizeGenLayerResult('Here is my assessment:\n{"verdict":"NEEDS_REVIEW","confidence":"LOW","findings":[]}\nHope this helps.');
  assert.equal(n.ok, true);
  assert.equal(n.value.verdict, 'NEEDS_REVIEW');
});

test('normalize: SDK envelope {result: "..."} is unwrapped and parsed', function () {
  var n = GenLayerClient.normalizeGenLayerResult({ result: '{"verdict":"NEEDS_REVIEW","confidence":"LOW","findings":[]}' });
  assert.equal(n.ok, true);
  assert.equal(n.value.verdict, 'NEEDS_REVIEW');
});

test('normalize: NO_ANALYSIS / empty / null => NO_RESULT', function () {
  assert.equal(GenLayerClient.normalizeGenLayerResult('NO_ANALYSIS').error, 'NO_RESULT');
  assert.equal(GenLayerClient.normalizeGenLayerResult('').error, 'NO_RESULT');
  assert.equal(GenLayerClient.normalizeGenLayerResult(null).error, 'NO_RESULT');
  assert.equal(GenLayerClient.normalizeGenLayerResult(undefined).error, 'NO_RESULT');
});

test('normalize: invalid JSON / non-string => INVALID_RESULT_JSON', function () {
  assert.equal(GenLayerClient.normalizeGenLayerResult('not json at all').error, 'INVALID_RESULT_JSON');
  assert.equal(GenLayerClient.normalizeGenLayerResult(42).error, 'INVALID_RESULT_JSON');
});

test('analyzeEvidence: markdown-fenced result is normalized end-to-end', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = {
      getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
      getTransaction: async function () { return { statusName: 'FINALIZED', status: 7, txExecutionResultName: 'FINISHED_WITH_RETURN' }; },
      readContract: async function () { return '```json\n{"verdict":"NEEDS_REVIEW","confidence":"LOW","findings":[]}\n```'; }
    };
    var write = { writeContract: async function () { return { hash: '0xabc123' }; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'studionet', networks: TEST_NETWORKS });
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  var resp = await a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  assert.equal(resp.verdict, 'NEEDS_REVIEW');
});

// ── auditor schema validation (actual contract output shape) ─────────────────

test('auditor: contract-shaped result passes; optional fields may be missing', function () {
  var v = Auditor.validateResponse({ verdict: 'NO_CONFIRMED_VULNERABILITY', confidence: 'HIGH', findings: [] }, {});
  assert.equal(v.valid, true);
  var v2 = Auditor.validateResponse({ verdict: 'NEEDS_REVIEW', confidence: 'LOW' }, {});
  assert.equal(v2.valid, true);
});

test('auditor: missing required verdict/confidence => invalid', function () {
  var v = Auditor.validateResponse({ findings: [] }, {});
  assert.equal(v.valid, false);
});

console.log('\nAll genlayer-runtime tests completed.');
