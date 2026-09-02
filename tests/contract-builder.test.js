'use strict';
// Phase 7 tests: Smart Contract Builder + GenLayer deployment adapter.
// Only the SDK transport is mocked (like genlayer-runtime.test.js) — never a
// fake deployment result or fabricated contract address.
// Run with:  node tests/contract-builder.test.js
const test = require('node:test');
const assert = require('node:assert');
const Builder = require('../public/contract-builder.js');
const GenLayerClient = require('../public/genlayer-client.js');
require('../public/genlayer-tx.js');

const TEST_NETWORKS = {
  studionet: { id: 'studionet', name: 'Studionet', chainId: 61999, rpc: 'https://studio.genlayer.com/api', contract: '0x' + 'ab'.repeat(20), deployed: true },
  bradbury:  { id: 'bradbury',  name: 'Bradbury',  chainId: 4221,  rpc: 'https://rpc-bradbury.genlayer.com', contract: '', deployed: false }
};

function mockSdk(deployImpl) {
  var writeClient = {
    deployContract: deployImpl || (async function () { return '0xhash123'; }),
    waitForTransactionReceipt: async function () { return { status: 'FINALIZED', txDataDecoded: { contractAddress: '0x' + 'cd'.repeat(20) } }; }
  };
  var readClient = {
    getContractSchema: async function () { return { methods: {} }; },
    getTransaction: async function () { return { statusName: 'FINALIZED', status: 7, txExecutionResultName: 'FINISHED_WITH_RETURN', txDataDecoded: { contractAddress: '0x' + 'cd'.repeat(20) } }; }
  };
  return {
    createClient: function (config) { return config && config.account ? writeClient : readClient; },
    chains: { studionet: { id: 61999, name: 'Studionet' }, testnetBradbury: { id: 4221, name: 'Bradbury' } }
  };
}

function makeAdapter(sdk, netId) {
  return GenLayerClient.createAdapter(sdk, { networkId: netId || 'studionet', networks: TEST_NETWORKS });
}

// ── Intent routing ───────────────────────────────────────────────────────────

test('CREATE_CONTRACT intent detected (no address)', function () {
  assert.equal(Builder.isCreateIntent('Create an ERC-20 token called MyToken with symbol MTK and 1 million initial supply'), true);
  assert.equal(Builder.isCreateIntent('Create a simple escrow contract where Alice deposits'), true);
  assert.equal(Builder.isCreateIntent('Build a storage contract with set and get'), true);
});

test('AUDIT_CONTRACT intent is NOT confused with CREATE_CONTRACT', function () {
  assert.equal(Builder.isCreateIntent('Audit this contract'), false);
  assert.equal(Builder.isCreateIntent('Scan 0xABC'), false);
  // With an address present, it is never a create intent.
  assert.equal(Builder.isCreateIntent('Create a token at 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', true), false);
});

// ── Specification parsing ────────────────────────────────────────────────────

test('parseSpec extracts ERC-20 name/symbol/supply', function () {
  var s = Builder.parseSpec('Create an ERC-20 token called MyToken with symbol MTK and 1 million initial supply');
  assert.equal(s.type, 'erc20');
  assert.equal(s.name, 'MyToken');
  assert.equal(s.symbol, 'MTK');
  assert.equal(s.supply, 1000000);
});

test('parseAmount handles units', function () {
  assert.equal(Builder.parseAmount('1 million'), 1000000);
  assert.equal(Builder.parseAmount('10k'), 10000);
  assert.equal(Builder.parseAmount('5000'), 5000);
  assert.equal(Builder.parseAmount('2 billion'), 2000000000);
});

test('parseSpec detects escrow and storage', function () {
  assert.equal(Builder.parseSpec('Create a simple escrow contract where Alice deposits').type, 'escrow');
  assert.equal(Builder.parseSpec('Create a storage contract').type, 'storage');
});

// ── Solidity generation ──────────────────────────────────────────────────────

test('generateSolidity produces valid ERC-20 with name/symbol/constructor', function () {
  var src = Builder.generateSolidity({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 });
  assert.ok(src.indexOf('contract MyToken') !== -1);
  assert.ok(src.indexOf('"MTK"') !== -1);
  assert.ok(src.indexOf('constructor(uint256 initialSupply)') !== -1);
  assert.ok(src.indexOf('function transfer(') !== -1);
  assert.equal(Builder.validateSolidity(src).valid, true);
});

test('generateSolidity produces valid storage and escrow contracts', function () {
  var st = Builder.generateSolidity({ type: 'storage', name: 'Storage' });
  assert.equal(Builder.validateSolidity(st).valid, true);
  assert.ok(st.indexOf('function set(') !== -1);
  assert.ok(st.indexOf('function get(') !== -1);

  var es = Builder.generateSolidity({ type: 'escrow', name: 'Escrow' });
  assert.equal(Builder.validateSolidity(es).valid, true);
  assert.ok(es.indexOf('function release(') !== -1);
});

test('generation is deterministic for identical specs', function () {
  var a = Builder.generateSolidity({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 });
  var b = Builder.generateSolidity({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 });
  assert.equal(a, b);
});

// ── Validation ───────────────────────────────────────────────────────────────

test('validateSolidity rejects empty / non-contract / unbalanced source', function () {
  assert.equal(Builder.validateSolidity('').valid, false);
  assert.equal(Builder.validateSolidity('hello world').valid, false);
  assert.equal(Builder.validateSolidity('contract X {').valid, false); // unbalanced
});

test('validateSolidity rejects embedded secrets', function () {
  var bad = 'pragma solidity ^0.8.20;\ncontract X { string private key = "abc"; }';
  var v = Builder.validateSolidity(bad);
  assert.equal(v.valid, false);
  assert.ok(v.errors.some(function (e) { return e.indexOf('secret') !== -1; }));
});

// ── Security warnings ────────────────────────────────────────────────────────

test('securityWarnings flags mintable and selfdestruct', function () {
  var w1 = Builder.securityWarnings({ type: 'erc20', mintable: true }, 'contract X {}');
  assert.ok(w1.some(function (w) { return w.level === 'HIGH'; }));

  var w2 = Builder.securityWarnings({ type: 'storage' }, 'contract X { function kill() { selfdestruct(payable(msg.sender)); } }');
  assert.ok(w2.some(function (w) { return w.text.indexOf('selfdestruct') !== -1; }));
});

test('securityWarnings does not flag a fixed-supply ERC-20 as HIGH', function () {
  var w = Builder.securityWarnings({ type: 'erc20', mintable: false }, 'contract X {}');
  assert.ok(!w.some(function (x) { return x.level === 'HIGH'; }));
});

// ── Constructor args / preview ───────────────────────────────────────────────

test('constructorArgs: ERC-20 initialSupply is deterministic wei string', function () {
  var args = Builder.constructorArgs({ type: 'erc20', supply: 1000000 });
  assert.equal(args.length, 1);
  assert.equal(args[0].name, 'initialSupply');
  assert.equal(args[0].value, '1000000000000000000000000'); // 1M * 10^18
});

test('constructorArgs: escrow requires beneficiary + approver addresses', function () {
  var args = Builder.constructorArgs({ type: 'escrow' });
  assert.equal(args.length, 2);
  assert.equal(args[0].type, 'address');
  assert.equal(args[1].type, 'address');
});

test('preview includes source, args, warnings, network', function () {
  var pv = Builder.preview({ type: 'erc20', name: 'T', symbol: 'T', supply: 100 }, Builder.generateSolidity({ type: 'erc20', name: 'T', symbol: 'T', supply: 100 }), { id: 'studionet', name: 'Studionet', chainId: 61999 });
  assert.ok(pv.source);
  assert.ok(pv.constructorArgs.length === 1);
  assert.ok(Array.isArray(pv.warnings));
  assert.equal(pv.network.chainId, 61999);
});

// ── GenLayer network config (Contract Builder targets) ──────────────────────

test('Studionet target is configured with chain 61999', function () {
  assert.equal(TEST_NETWORKS.studionet.chainId, 61999);
});

test('Bradbury target is configured with chain 4221 (no fabricated AuditAI address)', function () {
  assert.equal(TEST_NETWORKS.bradbury.chainId, 4221);
  assert.equal(TEST_NETWORKS.bradbury.contract, '');
});

// ── deployContract (mock SDK) ────────────────────────────────────────────────

test('deployContract: real hash + extracted address returned', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  var res = await a.deployContract('contract X {}', { account: '0x' + '11'.repeat(20) });
  assert.equal(res.hash, '0xhash123');
  assert.equal(res.contractAddress, '0x' + 'cd'.repeat(20));
});

test('deployContract: no account => WALLET_REQUIRED', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  await assert.rejects(function () { return a.deployContract('contract X {}', {}); }, /WALLET_REQUIRED/);
});

test('deployContract: empty code => CONTRACT_GENERATION_FAILED', async function () {
  var a = makeAdapter(mockSdk(), 'studionet');
  await assert.rejects(function () { return a.deployContract('', { account: '0x' + '11'.repeat(20) }); }, /CONTRACT_GENERATION_FAILED/);
});

test('deployContract: no tx hash => NO_TX_HASH', async function () {
  var sdk = mockSdk(async function () { return null; });
  var a = makeAdapter(sdk, 'studionet');
  await assert.rejects(function () { return a.deployContract('contract X {}', { account: '0x' + '11'.repeat(20) }); }, /NO_TX_HASH/);
});

test('deployContract: missing contract address => CONTRACT_ADDRESS_UNAVAILABLE', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var write = { deployContract: async function () { return '0xhash123'; }, waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; } };
    var read = { getContractSchema: async function () { return { methods: {} }; }, getTransaction: async function () { return { statusName: 'FINALIZED', status: 7 }; } };
    return config && config.account ? write : read;
  };
  var a = makeAdapter(sdk, 'studionet');
  await assert.rejects(function () { return a.deployContract('contract X {}', { account: '0x' + '11'.repeat(20) }); }, /CONTRACT_ADDRESS_UNAVAILABLE/);
});

test('deployContract: wallet rejection => USER_REJECTED', async function () {
  var sdk = mockSdk();
  sdk.createClient = function (config) {
    var write = {
      deployContract: async function () { var e = new Error('User rejected the request'); e.code = 4001; throw e; },
      waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
    };
    var read = { getContractSchema: async function () { return { methods: {} }; }, getTransaction: async function () { return { statusName: 'FINALIZED', status: 7 }; } };
    return config && config.account ? write : read;
  };
  var a = makeAdapter(sdk, 'studionet');
  await assert.rejects(function () { return a.deployContract('contract X {}', { account: '0x' + '11'.repeat(20) }); }, /USER_REJECTED/);
});

test('deployContract: unavailable SDK => SDK_UNAVAILABLE', async function () {
  var a = GenLayerClient.createAdapter({}, { networkId: 'studionet', networks: TEST_NETWORKS });
  await assert.rejects(function () { return a.deployContract('contract X {}', { account: '0x' + '11'.repeat(20) }); }, /SDK_UNAVAILABLE/);
});

test('extractContractAddress reads from receipt / txDataDecoded / data', function () {
  assert.equal(GenLayerClient.extractContractAddress({ contractAddress: '0xA' }), '0xA');
  assert.equal(GenLayerClient.extractContractAddress({ txDataDecoded: { contractAddress: '0xB' } }), '0xB');
  assert.equal(GenLayerClient.extractContractAddress({ data: { contractAddress: '0xC' } }), '0xC');
  assert.equal(GenLayerClient.extractContractAddress({}), null);
  assert.equal(GenLayerClient.extractContractAddress(null), null);
});

console.log('\nAll contract-builder tests completed.');
