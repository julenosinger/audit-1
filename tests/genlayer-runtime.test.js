'use strict';
// Phase 5B tests: GenLayer client adapter (real SDK shape, mocked transport).
// Only the transport is mocked — never a fake vulnerability result.
// Run with:  node tests/genlayer-runtime.test.js
const test = require('node:test');
const assert = require('node:assert');
const GenLayerClient = require('../public/genlayer-client.js');
const Auditor = require('../public/genlayer-auditor.js');
const Engine = require('../public/audit-engine.js');

function mockSdk() {
  var readClient = {
    getContractSchema: async function () {
      return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {}, publish_audit: {} } };
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
    chains: { testnetBradbury: { id: 4221, name: 'Bradbury', rpcUrls: { default: { http: ['https://rpc-bradbury.genlayer.com'] } } } }
  };
}

test('initialization: SDK loads and Bradbury chain id = 4221', function () {
  var a = GenLayerClient.createAdapter(mockSdk());
  assert.equal(a.isAvailable(), true);
  assert.equal(a.getNetwork().chainId, 4221);
  assert.ok(a.getReadClient());
});

test('contract schema exposes analyze_evidence and get_analysis', async function () {
  var a = GenLayerClient.createAdapter(mockSdk());
  var sch = await a.getContractSchema('0x' + 'ab'.repeat(20));
  assert.ok(sch.methods['analyze_evidence']);
  assert.ok(sch.methods['get_analysis']);
});

test('analyzeEvidence: full write → wait → read lifecycle returns parsed result', async function () {
  var a = GenLayerClient.createAdapter(mockSdk());
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  var resp = await a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20) });
  assert.equal(resp.verdict, 'NO_CONFIRMED_VULNERABILITY');
});

test('analyzeEvidence: no account => WALLET_REQUIRED', async function () {
  var a = GenLayerClient.createAdapter(mockSdk());
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20) });
  }, /WALLET_REQUIRED/);
});

test('analyzeEvidence: missing method => METHOD_MISSING', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    return {
      getContractSchema: async function () { return { ctor: {}, methods: {} }; }
    };
  };
  var a = GenLayerClient.createAdapter(sdk);
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20) });
  }, /METHOD_MISSING/);
});

test('analyzeEvidence: NO_ANALYSIS result => NO_RESULT', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = {
      getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
      readContract: async function () { return 'NO_ANALYSIS'; }
    };
    var write = { writeContract: async function () { return { hash: '0xabc123' }; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk);
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20) });
  }, /NO_RESULT/);
});

test('auditor integration: adapter + valid response => FINALIZED', async function () {
  var adapter = GenLayerClient.createAdapter(mockSdk());
  var local = Engine.analyze('600054f16000600155');
  var res = await Auditor.analyze(adapter, local, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20), timeoutMs: 2000 });
  assert.equal(res.status, 'FINALIZED');
  assert.ok(res.genlayer);
});

test('auditor integration: adapter without account => FAILED (local preserved)', async function () {
  var adapter = GenLayerClient.createAdapter(mockSdk());
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(adapter, local, { contractAddress: '0x' + 'ab'.repeat(20), timeoutMs: 2000 });
  assert.equal(res.status, 'FAILED');
  assert.equal(res.local, local);
  assert.equal(res.genlayer, null);
});

test('unavailable SDK => isAvailable false', function () {
  var a = GenLayerClient.createAdapter({});
  assert.equal(a.isAvailable(), false);
});

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

test('analyzeEvidence: no contract address => GENLAYER_AUDITOR_NOT_DEPLOYED', async function () {
  var a = GenLayerClient.createAdapter(mockSdk());
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20) });
  }, /GENLAYER_AUDITOR_NOT_DEPLOYED/);
});

test('analyzeEvidence emits onStatus lifecycle and surfaces the real tx hash', async function () {
  var a = GenLayerClient.createAdapter(mockSdk());
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  var states = [];
  var txHash = null;
  await a.analyzeEvidence(payload, {
    contractAddress: '0x' + 'ab'.repeat(20),
    account: '0x' + '11'.repeat(20),
    onStatus: function (s, d) { states.push(s); if (s === 'SUBMITTED') txHash = d; }
  });
  assert.deepEqual(states, ['PREPARING', 'CONNECTING', 'WAITING_WALLET', 'SUBMITTED', 'FINALIZING', 'RETRIEVING', 'COMPLETE']);
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
  var a = GenLayerClient.createAdapter(sdk);
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20) });
  }, /USER_REJECTED/);
});

test('analyzeEvidence: receipt timeout => TRANSACTION_TIMEOUT', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = { getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; }, readContract: async function () { return '{}'; } };
    var write = {
      writeContract: async function () { return { hash: '0xabc123' }; },
      waitForTransactionReceipt: async function () { throw new Error('Timed out waiting for transaction'); }
    };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk);
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20) });
  }, /TRANSACTION_TIMEOUT/);
});

test('analyzeEvidence: receipt status FAILED => TRANSACTION_FAILED', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var read = { getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; }, readContract: async function () { return '{}'; } };
    var write = {
      writeContract: async function () { return { hash: '0xabc123' }; },
      waitForTransactionReceipt: async function () { return { status: 'FAILED' }; }
    };
    return config && config.account ? write : read;
  };
  var a = GenLayerClient.createAdapter(sdk);
  var payload = { version: '5.0.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  await assert.rejects(function () {
    return a.analyzeEvidence(payload, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20) });
  }, /TRANSACTION_FAILED/);
});

test('auditor: emits VALIDATING/VALIDATED and surfaces error code', async function () {
  var adapter = GenLayerClient.createAdapter(mockSdk());
  var local = Engine.analyze('f1');
  var states = [];
  var res = await Auditor.analyze(adapter, local, { contractAddress: '0x' + 'ab'.repeat(20), account: '0x' + '11'.repeat(20), timeoutMs: 2000, onStatus: function (s) { states.push(s); } });
  assert.equal(res.status, 'FINALIZED');
  assert.ok(states.indexOf('VALIDATING') !== -1);
  assert.ok(states.indexOf('VALIDATED') !== -1);
});

test('auditor: no account surfaces WALLET_REQUIRED code via FAILED', async function () {
  var adapter = GenLayerClient.createAdapter(mockSdk());
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(adapter, local, { contractAddress: '0x' + 'ab'.repeat(20), timeoutMs: 2000 });
  assert.equal(res.status, 'FAILED');
  assert.equal(res.error, 'WALLET_REQUIRED');
});

console.log('\nAll genlayer-runtime tests completed.');
