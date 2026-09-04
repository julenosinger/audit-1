'use strict';
// Phase 8.0 (AuditAI v2) tests: append-only records bound to validator-fetched
// code/block. The contract is Python (contracts/audit_ai_v2.py); here we prove
// the JS contract-shape invariants with a mock that mirrors the on-chain
// storage (records keyed by id, monotonic next_id). Run with:
//   node tests/phase80-v2.test.js
const test = require('node:test');
const assert = require('node:assert');
const GenLayerClient = require('../public/genlayer-client.js');
const Verify = require('../public/genlayer-verify.js');
require('../public/genlayer-tx.js');

const TARGET = '0x' + 'ab'.repeat(20);
const ACCOUNT = '0x' + '11'.repeat(20);

// Mirrors the v2 contract storage semantics: a monotonic id counter, records
// keyed by id (written once), and an address -> ids list that only appends.
function mockV2Contract() {
  var nextId = 1;
  var records = {};    // id -> JSON string
  var idsByAddr = {};  // addr -> [ids]
  var calls = [];      // write function names (for the analyze_verified assertion)

  return {
    records: records,
    idsByAddr: idsByAddr,
    calls: calls,
    recordCount: function () { return Object.keys(records).length; },
    analyzeVerified: function (args) {
      var target = String(args[0]).toLowerCase();
      var chainId = args[1];
      var blockNumber = args[2];
      var id = String(nextId++);
      var rec = {
        id: id,
        target: target,
        chain_id: String(chainId),
        block_number: String(blockNumber),
        block_hash: '0x' + 'ab'.repeat(32),
        code_hash: '0x' + 'cd'.repeat(32),
        author: ACCOUNT,
        verdict: 'WARNING',
        summary: 'summary ' + id,
        source: 'verified'
      };
      records[id] = JSON.stringify(rec);
      (idsByAddr[target] = idsByAddr[target] || []).push(id);
      return { hash: '0x' + String(id).padStart(64, '0') };
    }
  };
}

function mockV2Sdk(contract) {
  var readClient = {
    getContractSchema: async function () {
      return { ctor: {}, methods: { analyze_verified: {}, latest_id: {}, get_record: {}, get_audit: {}, list_ids: {}, publish_audit: {}, analyze_and_publish: {}, analyze_evidence: {} } };
    },
    getTransaction: async function () {
      return { statusName: 'FINALIZED', status: 7, txExecutionResultName: 'FINISHED_WITH_RETURN' };
    },
    readContract: async function (a) {
      if (a.functionName === 'latest_id') {
        var ids = contract.idsByAddr[String(a.args[0]).toLowerCase()] || [];
        return ids.length ? ids[ids.length - 1] : '';
      }
      if (a.functionName === 'get_record') {
        return contract.records[a.args[0]] || 'NO_RECORD';
      }
      return '';
    }
  };
  var writeClient = {
    writeContract: async function (a) {
      contract.calls.push(a.functionName);
      if (a.functionName === 'analyze_verified') return contract.analyzeVerified(a.args);
      return { hash: '0xdeadbeef' };
    },
    waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
  };
  return {
    createClient: function (config) { return config && config.account ? writeClient : readClient; },
    chains: { studionet: { id: 61999 }, testnetBradbury: { id: 4221 } }
  };
}

function makeAdapter(contract) {
  return GenLayerClient.createAdapter(mockV2Sdk(contract || mockV2Contract()), { networkId: 'bradbury' });
}

// ── Registry points at the NEW v2 contract, not the recycled v1 address ─────

test('Bradbury registry points at the new v2 contract (not the v1 address)', function () {
  var reg = GenLayerClient.NETWORKS.bradbury;
  assert.equal(reg.contract.toLowerCase(), '0xc2c6914ced272031ecf0da4739bca74a8cbb7d76');
  assert.equal(reg.knownContract.toLowerCase(), '0xc2c6914ced272031ecf0da4739bca74a8cbb7d76');
  assert.notEqual(reg.contract.toLowerCase(), '0x119ac58af8546df0b0e55eb24277c756d9458000');
  var k = GenLayerClient.knownContractFor('0xc2c6914ced272031ecf0da4739bca74a8cbb7d76');
  assert.ok(k);
  assert.equal(k.chainId, 4221);
});

// ── Adapter submits the exact v2 method ──────────────────────────────────────

test('adapter analyzeVerified writes functionName analyze_verified', async function () {
  var contract = mockV2Contract();
  var a = makeAdapter(contract);
  var out = await a.analyzeVerified(TARGET, 1, 'latest', { account: ACCOUNT });
  assert.equal(contract.calls[0], 'analyze_verified');
  assert.ok(out.id);
  assert.equal(out.record.code_hash, '0x' + 'cd'.repeat(32));
  assert.equal(out.record.block_hash, '0x' + 'ab'.repeat(32));
});

// ── Two writes to the same addr -> two ids; record 1 intact ─────────────────

test('two analyzeVerified writes to the same addr produce two ids; record 1 intact', async function () {
  var contract = mockV2Contract();
  var a = makeAdapter(contract);
  var r1 = await a.analyzeVerified(TARGET, 1, 'latest', { account: ACCOUNT });
  var r2 = await a.analyzeVerified(TARGET, 1, 'latest', { account: ACCOUNT });

  assert.notEqual(r1.id, r2.id);
  assert.equal(contract.recordCount(), 2);

  // record 1 is never edited after the second write.
  var rec1 = JSON.parse(contract.records[r1.id]);
  assert.equal(rec1.id, r1.id);
  assert.equal(rec1.code_hash, r1.record.code_hash);
  assert.equal(rec1.block_hash, r1.record.block_hash);
  assert.equal(rec1.target, TARGET);

  // ids_by_addr only appends: both ids present, in order.
  var ids = contract.idsByAddr[TARGET];
  assert.deepEqual(ids, [r1.id, r2.id]);
});

// ── no account -> WALLET_REQUIRED ────────────────────────────────────────────

test('adapter analyzeVerified without account => WALLET_REQUIRED', async function () {
  var a = makeAdapter();
  await assert.rejects(function () {
    return a.analyzeVerified(TARGET, 1, 'latest', {});
  }, /WALLET_REQUIRED/);
});

// ── verify module: analyze_verified action ──────────────────────────────────

test('verify: analyze_verified with code_hash + block_hash => VERIFIED_ON_CHAIN', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'analyze_verified',
    txHash: '0x' + 'ab'.repeat(32),
    contractAddress: '0x' + '11'.repeat(20),
    networkId: 'bradbury',
    chainId: 4221,
    expected: { target: TARGET, chainId: '1' },
    state: { record: { id: '1', target: TARGET, chain_id: '1', code_hash: '0x' + 'cd'.repeat(32), block_hash: '0x' + 'ab'.repeat(32) } }
  });
  assert.equal(v.verified, true);
  assert.equal(v.status, 'VERIFIED_ON_CHAIN');
  assert.ok(v.matchedFields.indexOf('code_hash') !== -1);
  assert.ok(v.matchedFields.indexOf('block_hash') !== -1);
});

test('verify: analyze_verified missing code_hash => VERIFICATION_FAILED (never verified)', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'analyze_verified',
    txHash: '0x' + 'ab'.repeat(32),
    contractAddress: '0x' + '11'.repeat(20),
    networkId: 'bradbury',
    chainId: 4221,
    expected: { target: TARGET, chainId: '1' },
    state: { record: { id: '2', target: TARGET, chain_id: '1', code_hash: '', block_hash: '0x' + 'ab'.repeat(32) } }
  });
  assert.equal(v.verified, false);
  assert.equal(v.status, 'VERIFICATION_FAILED');
  assert.ok(v.mismatchFields.indexOf('code_hash') !== -1);
});

test('verify: analyze_verified missing block_hash => VERIFICATION_FAILED', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'analyze_verified',
    txHash: '0x' + 'ab'.repeat(32),
    contractAddress: '0x' + '11'.repeat(20),
    networkId: 'bradbury',
    chainId: 4221,
    expected: { target: TARGET, chainId: '1' },
    state: { record: { id: '3', target: TARGET, chain_id: '1', code_hash: '0x' + 'cd'.repeat(32), block_hash: '' } }
  });
  assert.equal(v.verified, false);
  assert.equal(v.status, 'VERIFICATION_FAILED');
});

test('verify: analyze_verified with no record read => VERIFICATION_PENDING', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'analyze_verified',
    txHash: '0x' + 'ab'.repeat(32),
    contractAddress: '0x' + '11'.repeat(20),
    networkId: 'bradbury',
    chainId: 4221,
    expected: { target: TARGET, chainId: '1' },
    state: {}
  });
  assert.equal(v.verified, false);
  assert.equal(v.status, 'VERIFICATION_PENDING');
});

test('parseRecord accepts JSON string and object, rejects NO_RECORD', function () {
  var obj = { id: '1', code_hash: '0x' + 'cd'.repeat(32) };
  assert.deepEqual(Verify.parseRecord(JSON.stringify(obj)), obj);
  assert.deepEqual(Verify.parseRecord(obj), obj);
  assert.equal(Verify.parseRecord('NO_RECORD'), null);
  assert.equal(Verify.parseRecord(null), null);
  assert.equal(Verify.parseRecord('not json'), null);
});

console.log('\nAll phase80-v2 tests completed.');
