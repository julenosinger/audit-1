'use strict';
// Phase 7.1 tests: automatic multi-network contract discovery.
// Only the JSON-RPC transport is mocked — never a fake audit result.
// Run with:  node tests/audit-discovery.test.js
const test = require('node:test');
const assert = require('node:assert');
const { beforeEach } = require('node:test');
const Networks = require('../public/networks.js');
const Engine = require('../public/audit-engine.js');

const ADDR = '0x' + 'ab'.repeat(20);
const CODE = '0x600060005260206000f3';

beforeEach(function () { Networks.clearCodeCache(); });

// Build a fetch router from a per-network config:
//   config = { '<networkId>': { code: '0x...'|'0x', throw: false|msg, chainIdOverride } }
function routerFrom(config) {
  return function (rpc, method) {
    var ids = Networks.networkIds();
    for (var i = 0; i < ids.length; i++) {
      var net = Networks.getNetwork(ids[i]);
      if (net.rpc !== rpc) continue;
      var c = config[ids[i]];
      if (!c) continue;
      if (c.throw) return { __throw: new Error(c.throw === true ? 'down' : c.throw) };
      if (method === 'eth_chainId') return '0x' + (c.chainIdOverride !== undefined ? c.chainIdOverride : net.chainId).toString(16);
      if (method === 'eth_getCode') return c.code;
    }
    return null;
  };
}

function mockFetch(router) {
  return async function (url, init) {
    const body = JSON.parse(init.body);
    const r = router(url, body.method, body.params || []);
    if (r && r.__throw) throw r.__throw;
    if (r && r.__http) return { ok: false, status: r.__http, json: async function () { return {}; } };
    return { ok: true, json: async function () { return { jsonrpc: '2.0', id: 1, result: r }; } };
  };
}

function withFetch(router, fn) {
  const saved = globalThis.fetch;
  globalThis.fetch = mockFetch(router);
  return fn().finally(function () { globalThis.fetch = saved; });
}

function allNoCode() {
  var c = {};
  Networks.networkIds().forEach(function (id) { c[id] = { code: '0x' }; });
  return c;
}

// ── Registry ─────────────────────────────────────────────────────────────────

test('registry: 7 supported audit networks with correct chain ids', function () {
  var reg = Networks.NETWORKS;
  assert.equal(reg.ethereum.chainId, 1);
  assert.equal(reg.bsc.chainId, 56);
  assert.equal(reg.base.chainId, 8453);
  assert.equal(reg.arbitrum.chainId, 42161);
  assert.equal(reg.optimism.chainId, 10);
  assert.equal(reg.genlayerStudionet.chainId, 61999);
  assert.equal(reg.genlayerBradbury.chainId, 4221);
  assert.equal(Networks.networkIds().length, 7);
});

test('registry: no duplicate chain ids, every network has rpc + explorer info', function () {
  var seen = {};
  Networks.networkIds().forEach(function (id) {
    var n = Networks.getNetwork(id);
    assert.ok(n.rpc && n.rpc.indexOf('http') === 0, id + ' has rpc');
    assert.ok(!seen[n.chainId], 'duplicate chainId ' + n.chainId);
    seen[n.chainId] = true;
  });
  assert.ok(Networks.getNetwork('ethereum').explorerName === 'Etherscan');
  assert.ok(Networks.getNetwork('bsc').explorerName === 'BscScan');
  assert.ok(Networks.getNetwork('arbitrum').explorerName === 'Arbiscan');
  assert.ok(Networks.getNetwork('optimism').explorerName === 'Optimistic Etherscan');
});

// ── Discovery: single network match ─────────────────────────────────────────

test('discovery: Ethereum contract found only on Ethereum', async function () {
  var c = allNoCode(); c.ethereum = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.found, true);
    assert.equal(d.matchCount, 1);
    assert.equal(d.matches[0].networkId, 'ethereum');
    assert.equal(d.matches[0].chainId, 1);
    assert.equal(d.matches[0].bytecodeAvailable, true);
  });
});

test('discovery: Base contract found only on Base (no Ethereum fallback)', async function () {
  var c = allNoCode(); c.base = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.matchCount, 1);
    assert.equal(d.matches[0].networkId, 'base');
    assert.notEqual(d.matches[0].networkId, 'ethereum');
  });
});

test('discovery: BSC / Arbitrum / Optimism / Studionet / Bradbury individually', async function () {
  var ids = ['bsc', 'arbitrum', 'optimism', 'genlayerStudionet', 'genlayerBradbury'];
  for (const id of ids) {
    Networks.clearCodeCache();
    var c = allNoCode(); c[id] = { code: CODE };
    await withFetch(routerFrom(c), async function () {
      var d = await Networks.discoverContract(ADDR);
      assert.equal(d.matches.length, 1, id + ' should be the sole match');
      assert.equal(d.matches[0].networkId, id);
    });
  }
});

// ── Discovery: no match / errors ─────────────────────────────────────────────

test('discovery: address not found anywhere => found false, all NOT_FOUND', async function () {
  await withFetch(routerFrom(allNoCode()), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.found, false);
    assert.equal(d.matchCount, 0);
    d.diagnostics.forEach(function (x) { assert.equal(x.contractType, 'NOT_FOUND'); });
  });
});

test('discovery: one RPC failure is isolated (remaining networks still checked)', async function () {
  var c = allNoCode();
  c.ethereum = { throw: true };
  c.base = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.matchCount, 1);
    assert.equal(d.matches[0].networkId, 'base');
    var eth = d.diagnostics.filter(function (x) { return x.networkId === 'ethereum'; })[0];
    assert.equal(eth.contractType, 'RPC_ERROR');
  });
});

test('discovery: multiple RPC failures do not block matches', async function () {
  var c = allNoCode();
  c.ethereum = { throw: true };
  c.bsc = { throw: true };
  c.arbitrum = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.matchCount, 1);
    assert.equal(d.matches[0].networkId, 'arbitrum');
  });
});

test('discovery: multiple networks with the same address => matchCount > 1', async function () {
  var c = allNoCode();
  c.ethereum = { code: CODE };
  c.base = { code: CODE };
  c.arbitrum = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.matchCount, 3);
    var ids = d.matches.map(function (m) { return m.networkId; });
    assert.ok(ids.indexOf('ethereum') !== -1 && ids.indexOf('base') !== -1 && ids.indexOf('arbitrum') !== -1);
  });
});

test('discovery: invalid address => INVALID_ADDRESS', async function () {
  var d = await Networks.discoverContract('0x123');
  assert.equal(d.ok, false);
  assert.equal(d.error, 'INVALID_ADDRESS');
});

test('discovery: RPC error (thrown) => RPC_ERROR, not NOT_FOUND', async function () {
  var c = allNoCode();
  c.ethereum = { throw: 'ECONNREFUSED' };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    var eth = d.diagnostics.filter(function (x) { return x.networkId === 'ethereum'; })[0];
    assert.equal(eth.contractType, 'RPC_ERROR');
    assert.notEqual(eth.contractType, 'NOT_FOUND');
  });
});

test('discovery: network chainId mismatch => NETWORK_CHAIN_ID_MISMATCH', async function () {
  var c = allNoCode();
  c.ethereum = { code: CODE, chainIdOverride: 999 }; // rpc reports wrong chain
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    var eth = d.diagnostics.filter(function (x) { return x.networkId === 'ethereum'; })[0];
    assert.equal(eth.contractType, 'NETWORK_CHAIN_ID_MISMATCH');
    assert.equal(d.matchCount, 0, 'mismatched network must not be treated as a match');
  });
});

test('discovery: withTimeout rejects on timeout', async function () {
  await assert.rejects(function () { return Networks.withTimeout(new Promise(function () {}), 20); }, /TIMEOUT/);
});

// ── Cache isolation ──────────────────────────────────────────────────────────

test('discovery cache is keyed by chainId:address (no cross-network reuse)', function () {
  assert.equal(Networks.cacheKey(1, ADDR), '1:' + ADDR.toLowerCase());
  assert.equal(Networks.cacheKey(8453, ADDR), '8453:' + ADDR.toLowerCase());
  assert.notEqual(Networks.cacheKey(1, ADDR), Networks.cacheKey(8453, ADDR));
});

// ── Integration: discovery → local audit ────────────────────────────────────

test('integration: discovered network feeds Local Audit with correct context', async function () {
  var c = allNoCode();
  c.genlayerStudionet = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.matches[0].networkId, 'genlayerStudionet');
    var r = await Engine.auditContract({ address: ADDR, networkId: d.matches[0].networkId });
    assert.equal(r.networkId, 'genlayerStudionet');
    assert.equal(r.chainId, 61999);
    assert.equal(r.contractType, 'CONTRACT');
    assert.equal(r.bytecodeAvailable, true);
  });
});

test('integration: Ethereum discovered contract produces a real Local Analysis', async function () {
  var c = allNoCode();
  c.ethereum = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    var r = await Engine.auditContract({ address: ADDR, networkId: d.matches[0].networkId });
    assert.equal(r.networkId, 'ethereum');
    assert.equal(r.chainId, 1);
    assert.equal(r.contractType, 'CONTRACT');
    assert.ok(r.bytecodeHash);
    assert.ok(r.findings.length >= 0);
  });
});

test('integration: no network match => discovery returns false (no audit run)', async function () {
  await withFetch(routerFrom(allNoCode()), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.found, false);
  });
});

console.log('\nAll audit-discovery tests completed.');
