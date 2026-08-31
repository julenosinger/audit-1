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

console.log('\nAll genlayer-runtime tests completed.');
