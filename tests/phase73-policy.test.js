'use strict';
// Phase 7.3 tests: GenLayer-first network policy + read-only external networks.
// Run with:  node tests/phase73-policy.test.js
const test = require('node:test');
const assert = require('node:assert');
const { beforeEach } = require('node:test');
const GenLayerClient = require('../public/genlayer-client.js');
const Templates = require('../public/contract-templates.js');
const Networks = require('../public/networks.js');

const AUDITAI = '0xF2c549Bf2Dc106a28354B1444298DD460601856B';
const ADDR = '0x' + 'ab'.repeat(20);
const CODE = '0x600060005260206000f3';

beforeEach(function () { Networks.clearCodeCache(); });

// ── GenLayer Bradbury is the default transaction/deployment network ──────────

test('GenLayer default transaction network is Bradbury', function () {
  assert.equal(GenLayerClient.DEFAULT_NETWORK_ID, 'bradbury');
});

test('Studionet chain id is 61999 and AuditAI contract is configured', function () {
  assert.equal(GenLayerClient.NETWORKS.studionet.chainId, 61999);
  assert.equal(GenLayerClient.NETWORKS.studionet.contract.toLowerCase(), AUDITAI.toLowerCase());
  assert.equal(GenLayerClient.NETWORKS.studionet.deployed, true);
});

test('Bradbury chain id is 4221; known contract + deployment tx registered', function () {
  assert.equal(GenLayerClient.NETWORKS.bradbury.chainId, 4221);
  assert.equal(GenLayerClient.NETWORKS.bradbury.deployed, true); // AuditAI deployed on Bradbury
  assert.equal(GenLayerClient.NETWORKS.bradbury.contract.toLowerCase(), '0x119ac58af8546df0b0e55eb24277c756d9458000');
  assert.equal(GenLayerClient.NETWORKS.bradbury.knownDeploymentTx, '0x79b33023be587678e6419526462209168598a1b5b20279dc45ef904b5561cabc');
  assert.equal(GenLayerClient.DEFAULT_NETWORK_ID, 'bradbury');
});

// ── External EVM networks are read-only audit targets ────────────────────────

test('audit registry supports external EVM networks for read-only discovery', function () {
  var reg = Networks.NETWORKS;
  assert.equal(reg.ethereum.chainId, 1);
  assert.equal(reg.bsc.chainId, 56);
  assert.equal(reg.base.chainId, 8453);
  assert.equal(reg.arbitrum.chainId, 42161);
  assert.equal(reg.optimism.chainId, 10);
});

test('networks module exposes NO write/deploy API (read-only audit only)', function () {
  ['deployContract', 'writeContract', 'sendTransaction', 'signTransaction'].forEach(function (k) {
    assert.equal(Networks[k], undefined, 'networks.js must not expose ' + k);
  });
});

// ── No external EVM deployment (GENLAYER_ONLY_DEPLOYMENT) ────────────────────

test('EVM Solidity contract on EVM network => GENLAYER_ONLY_DEPLOYMENT', function () {
  var c = Templates.deploymentCapability({ type: 'erc20' }, 'EVM');
  assert.equal(c.supported, false);
  assert.equal(c.code, 'GENLAYER_ONLY_DEPLOYMENT');
});

test('EVM Solidity contract on GenLayer network => GENLAYER_ONLY_DEPLOYMENT (no silent conversion)', function () {
  var c = Templates.deploymentCapability({ type: 'erc20' }, 'GENLAYER');
  assert.equal(c.supported, false);
  assert.equal(c.code, 'GENLAYER_ONLY_DEPLOYMENT');
});

test('GenLayer contract on GenLayer network => SUPPORTED (chain 61999)', function () {
  var c = Templates.deploymentCapability({ type: 'genlayer_intelligent' }, 'GENLAYER');
  assert.equal(c.supported, true);
  assert.equal(c.code, 'SUPPORTED');
});

test('GenLayer contract on EVM network => GENLAYER_ONLY_DEPLOYMENT', function () {
  var c = Templates.deploymentCapability({ type: 'genlayer_intelligent' }, 'EVM');
  assert.equal(c.supported, false);
  assert.equal(c.code, 'GENLAYER_ONLY_DEPLOYMENT');
});

// ── No Ethereum fallback (audit discovery preserved) ─────────────────────────

function routerFrom(config) {
  return function (rpc, method) {
    var ids = Networks.networkIds();
    for (var i = 0; i < ids.length; i++) {
      var net = Networks.getNetwork(ids[i]);
      if (net.rpc !== rpc) continue;
      var c = config[ids[i]];
      if (!c) continue;
      if (c.throw) return { __throw: new Error('down') };
      if (method === 'eth_chainId') return '0x' + net.chainId.toString(16);
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
    return { ok: true, json: async function () { return { jsonrpc: '2.0', id: 1, result: r }; } };
  };
}
function withFetch(router, fn) {
  const saved = globalThis.fetch;
  globalThis.fetch = mockFetch(router);
  return fn().finally(function () { globalThis.fetch = saved; });
}

test('discovery: Base-only contract is never assumed to be Ethereum', async function () {
  var c = {};
  Networks.networkIds().forEach(function (id) { c[id] = { code: '0x' }; });
  c.base = { code: CODE };
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.matches.length, 1);
    assert.equal(d.matches[0].networkId, 'base');
    assert.notEqual(d.matches[0].networkId, 'ethereum');
  });
});

test('discovery: no network match => honest no-bytecode (not Ethereum default)', async function () {
  var c = {};
  Networks.networkIds().forEach(function (id) { c[id] = { code: '0x' }; });
  await withFetch(routerFrom(c), async function () {
    var d = await Networks.discoverContract(ADDR);
    assert.equal(d.found, false);
  });
});

console.log('\nAll phase73-policy tests completed.');
