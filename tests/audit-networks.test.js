'use strict';
// Phase 6.5 tests: Network Registry + RPC preflight + network-aware bytecode.
// Only the JSON-RPC transport is mocked — never a fake audit result or bytecode.
// Run with:  node tests/audit-networks.test.js
const test = require('node:test');
const assert = require('node:assert');
const { beforeEach } = require('node:test');
const Networks = require('../public/networks.js');
const Engine = require('../public/audit-engine.js');
const GenLayerClient = require('../public/genlayer-client.js');

const ADDR = '0x' + 'ab'.repeat(20);
const STUDIO_CONTRACT = '0xF2c549Bf2Dc106a28354B1444298DD460601856B';

beforeEach(function () { Networks.clearCodeCache(); });

// ── fetch mock (routes JSON-RPC calls by url + method + params) ──────────────
// A route result can be:
//   value                    -> { jsonrpc, id, result: value }
//   { __rpcError: 'msg' }    -> { jsonrpc, id, error: { message } }
//   { __http: 500 }          -> HTTP error (res.ok === false)
//   { __badJson: true }      -> res.json() throws (malformed body)
//   { __throw: Error }       -> fetch() rejects (network unavailable)
function mockFetch(router) {
  return async function (url, init) {
    const body = JSON.parse(init.body);
    const method = body.method;
    const params = body.params || [];
    const r = router(url, method, params);
    if (r && r.__throw) throw r.__throw;
    if (r && r.__http) return { ok: false, status: r.__http, json: async function () { return {}; } };
    if (r && r.__badJson) return { ok: true, json: async function () { throw new Error('malformed json'); } };
    if (r && r.__rpcError) return { ok: true, json: async function () { return { jsonrpc: '2.0', id: 1, error: { code: -32000, message: r.__rpcError } }; } };
    return { ok: true, json: async function () { return { jsonrpc: '2.0', id: 1, result: r }; } };
  };
}

function withFetch(router, fn) {
  const saved = globalThis.fetch;
  globalThis.fetch = mockFetch(router);
  return fn().finally(function () { globalThis.fetch = saved; });
}

// ── Network registry ─────────────────────────────────────────────────────────

test('registry: Ethereum / Studionet / Bradbury with correct chain ids', function () {
  const reg = Networks.NETWORKS;
  assert.equal(reg.ethereum.chainId, 1);
  assert.equal(reg.ethereum.name, 'Ethereum');
  assert.equal(reg.genlayerStudionet.chainId, 61999);
  assert.equal(reg.genlayerStudionet.name, 'GenLayer Studionet');
  assert.equal(reg.genlayerBradbury.chainId, 4221);
  assert.equal(reg.genlayerBradbury.name, 'GenLayer Bradbury');
});

test('registry: no duplicate chain ids', function () {
  const ids = Networks.networkIds();
  const seen = {};
  ids.forEach(function (id) {
    const chainId = Networks.getNetwork(id).chainId;
    assert.equal(seen[chainId], undefined, 'duplicate chainId ' + chainId);
    seen[chainId] = true;
  });
});

test('registry: every network has an RPC (never invented — matches project config)', function () {
  Networks.networkIds().forEach(function (id) {
    const n = Networks.getNetwork(id);
    assert.ok(typeof n.rpc === 'string' && n.rpc.slice(0, 4) === 'http', id + ' has a URL rpc');
  });
});

test('registry: GenLayer audit networks map onto GenLayer execution network ids', function () {
  assert.equal(Networks.GENLAYER_NETWORK_MAP.genlayerStudionet, 'studionet');
  assert.equal(Networks.GENLAYER_NETWORK_MAP.genlayerBradbury, 'bradbury');
  // The GenLayer execution registry stays separate and honest for Bradbury.
  assert.equal(GenLayerClient.NETWORKS.bradbury.deployed, false);
  assert.equal(GenLayerClient.NETWORKS.studionet.deployed, true);
});

// ── Address validation ───────────────────────────────────────────────────────

test('address validation accepts 0x + 40 hex, rejects malformed', function () {
  assert.equal(Networks.isValidAddress(ADDR), true);
  assert.equal(Networks.isValidAddress('0x' + 'AB'.repeat(20)), true);
  assert.equal(Networks.isValidAddress('0x123'), false);
  assert.equal(Networks.isValidAddress('abc'), false);
  assert.equal(Networks.isValidAddress('0x' + 'gg'.repeat(20)), false);
  assert.equal(Networks.isValidAddress(null), false);
  assert.equal(Networks.isValidAddress(undefined), false);
});

test('normalizeAddress lowercases and never silently rewrites the display value', function () {
  const n = Networks.normalizeAddress('0x' + 'AB'.repeat(20));
  assert.equal(n.valid, true);
  assert.equal(n.address, '0x' + 'ab'.repeat(20));
  const bad = Networks.normalizeAddress('not-an-address');
  assert.equal(bad.valid, false);
  assert.equal(bad.address, null);
});

// ── RPC preflight ────────────────────────────────────────────────────────────

test('preflight: correct chain passes', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0x1';
    return null;
  }, async function () {
    const pf = await Networks.preflight('https://rpc.example', 1);
    assert.equal(pf.ok, true);
    assert.equal(pf.chainId, 1);
  });
});

test('preflight: wrong chain => NETWORK_CHAIN_ID_MISMATCH', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0x2';
    return null;
  }, async function () {
    const pf = await Networks.preflight('https://rpc.example', 1);
    assert.equal(pf.ok, false);
    assert.equal(pf.error, 'NETWORK_CHAIN_ID_MISMATCH');
    assert.equal(pf.chainId, 2);
    assert.equal(pf.expectedChainId, 1);
  });
});

test('preflight: RPC unavailable => RPC_ERROR', async function () {
  await withFetch(function () {
    return { __throw: new Error('ECONNREFUSED') };
  }, async function () {
    const pf = await Networks.preflight('https://rpc.example', 1);
    assert.equal(pf.ok, false);
    assert.equal(pf.error, 'RPC_ERROR');
  });
});

test('preflight: malformed response (JSON-RPC error) => RPC_ERROR', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return { __rpcError: 'invalid request' };
    return null;
  }, async function () {
    const pf = await Networks.preflight('https://rpc.example', 1);
    assert.equal(pf.ok, false);
    assert.equal(pf.error, 'RPC_ERROR');
  });
});

test('preflight: malformed HTTP body (bad json) => RPC_ERROR', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return { __badJson: true };
    return null;
  }, async function () {
    const pf = await Networks.preflight('https://rpc.example', 1);
    assert.equal(pf.ok, false);
    assert.equal(pf.error, 'RPC_ERROR');
  });
});

// ── Bytecode fetch / classification ─────────────────────────────────────────

test('getCode returns bytecode from eth_getCode', async function () {
  await withFetch(function (url, method, params) {
    if (method === 'eth_getCode') return '0x60006000';
    return null;
  }, async function () {
    const code = await Networks.getCode('https://rpc.example', ADDR, 1, { useCache: false });
    assert.equal(code, '0x60006000');
  });
});

test('getCode: RPC failure throws', async function () {
  await withFetch(function () { return { __throw: new Error('down') }; }, async function () {
    await assert.rejects(function () { return Networks.getCode('https://rpc.example', ADDR, 1, { useCache: false }); });
  });
});

test('classifyContract: CONTRACT / EOA / NOT_FOUND / NO_BYTECODE / RPC_ERROR / mismatch / invalid', function () {
  assert.equal(Networks.classifyContract('0x6000'), 'CONTRACT');
  assert.equal(Networks.classifyContract('0x', { accountActive: true }), 'EOA');
  assert.equal(Networks.classifyContract('0x', { accountActive: false }), 'NOT_FOUND');
  assert.equal(Networks.classifyContract('0x', { accountActive: null }), 'NO_BYTECODE');
  assert.equal(Networks.classifyContract('0x', { status: 'RPC_ERROR' }), 'RPC_ERROR');
  assert.equal(Networks.classifyContract('0x', { status: 'NETWORK_CHAIN_ID_MISMATCH' }), 'NETWORK_CHAIN_ID_MISMATCH');
  assert.equal(Networks.classifyContract('0x', { status: 'INVALID_ADDRESS' }), 'INVALID_ADDRESS');
});

test('empty eth_getCode is NEVER automatically EOA — reason is derived from context', function () {
  // No account activity => NOT_FOUND, not EOA.
  assert.notEqual(Networks.classifyContract('0x', { accountActive: false }), 'EOA');
});

// ── auditContext (validate → preflight → fetch → classify) ──────────────────

test('auditContext: valid address + contract code => CONTRACT, bytecode available', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0xf22f'; // 61999
    if (method === 'eth_getCode') return '0x60006000';
    return null;
  }, async function () {
    const ctx = await Networks.auditContext('genlayerStudionet', ADDR);
    assert.equal(ctx.ok, true);
    assert.equal(ctx.contractType, 'CONTRACT');
    assert.equal(ctx.bytecodeAvailable, true);
    assert.equal(ctx.networkName, 'GenLayer Studionet');
    assert.equal(ctx.chainId, 61999);
    assert.equal(ctx.networkStatus.bytecode, 'found');
  });
});

test('auditContext: empty code + active account => EOA', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0xf22f';
    if (method === 'eth_getCode') return '0x';
    if (method === 'eth_getTransactionCount') return '0x5';
    if (method === 'eth_getBalance') return '0x0';
    return null;
  }, async function () {
    const ctx = await Networks.auditContext('genlayerStudionet', ADDR);
    assert.equal(ctx.ok, true);
    assert.equal(ctx.contractType, 'EOA');
    assert.equal(ctx.bytecodeAvailable, false);
  });
});

test('auditContext: empty code + no activity => NOT_FOUND', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0x1';
    if (method === 'eth_getCode') return '0x';
    if (method === 'eth_getTransactionCount') return '0x0';
    if (method === 'eth_getBalance') return '0x0';
    return null;
  }, async function () {
    const ctx = await Networks.auditContext('ethereum', ADDR);
    assert.equal(ctx.contractType, 'NOT_FOUND');
    assert.equal(ctx.bytecodeAvailable, false);
  });
});

test('auditContext: invalid address => INVALID_ADDRESS', async function () {
  const ctx = await Networks.auditContext('ethereum', '0x123');
  assert.equal(ctx.ok, false);
  assert.equal(ctx.contractType, 'INVALID_ADDRESS');
});

test('auditContext: unknown network => RPC_ERROR / UNKNOWN_NETWORK', async function () {
  const ctx = await Networks.auditContext('doesNotExist', ADDR);
  assert.equal(ctx.ok, false);
  assert.equal(ctx.error, 'UNKNOWN_NETWORK');
});

test('auditContext: chain id mismatch => NETWORK_CHAIN_ID_MISMATCH', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0x2';
    return null;
  }, async function () {
    const ctx = await Networks.auditContext('genlayerStudionet', ADDR);
    assert.equal(ctx.ok, false);
    assert.equal(ctx.contractType, 'NETWORK_CHAIN_ID_MISMATCH');
    assert.equal(ctx.error, 'NETWORK_CHAIN_ID_MISMATCH');
  });
});

// ── Cross-network isolation ──────────────────────────────────────────────────

test('cache key MUST include chainId + address (never address alone)', function () {
  const k1 = Networks.cacheKey(1, ADDR);
  const k2 = Networks.cacheKey(61999, ADDR);
  assert.notEqual(k1, k2);
  assert.equal(k1, '1:' + ADDR.toLowerCase());
  assert.equal(k2, '61999:' + ADDR.toLowerCase());
});

test('bytecode cache is network-aware: same address, two networks, two fetches', async function () {
  let calls = 0;
  await withFetch(function (url, method) {
    if (method === 'eth_getCode') { calls++; return calls === 1 ? '0x6000' : '0x60f3'; }
    return null;
  }, async function () {
    Networks.clearCodeCache();
    const a = await Networks.getCode('https://rpc.example', ADDR, 1);   // ethereum -> 0x6000
    const b = await Networks.getCode('https://rpc.example', ADDR, 61999); // studionet -> 0x60f3
    const a2 = await Networks.getCode('https://rpc.example', ADDR, 1);  // cache hit (0x6000)
    assert.equal(a, '0x6000');
    assert.equal(b, '0x60f3');
    assert.equal(a2, '0x6000');
    assert.equal(calls, 2, 'third call must be a cache hit, not a fresh fetch');
    Networks.clearCodeCache();
  });
});

test('engine auditContract: same address on two networks yields different contexts', async function () {
  // The real GenLayer contract has code on Studionet but none on Ethereum.
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return url.indexOf('studio') !== -1 ? '0xf22f' : '0x1';
    if (method === 'eth_getCode') {
      return url.indexOf('studio') !== -1 ? '0x600060005260206000f3' : '0x';
    }
    if (method === 'eth_getTransactionCount') return '0x0';
    if (method === 'eth_getBalance') return '0x0';
    return null;
  }, async function () {
    const onStudionet = await Engine.auditContract({ address: STUDIO_CONTRACT, networkId: 'genlayerStudionet' });
    const onEthereum = await Engine.auditContract({ address: STUDIO_CONTRACT, networkId: 'ethereum' });

    assert.equal(onStudionet.contractType, 'CONTRACT');
    assert.equal(onStudionet.bytecodeAvailable, true);
    assert.equal(onStudionet.networkId, 'genlayerStudionet');
    assert.equal(onStudionet.chainId, 61999);
    assert.equal(onStudionet.networkName, 'GenLayer Studionet');

    assert.equal(onEthereum.contractType, 'NOT_FOUND');
    assert.equal(onEthereum.bytecodeAvailable, false);
    assert.equal(onEthereum.chainId, 1);
    assert.equal(onEthereum.risk.level, 'LIMITED ANALYSIS');

    // Bytecode hashes must differ (different bytecode, different network).
    assert.ok(onStudionet.bytecodeHash);
    assert.notEqual(onStudionet.bytecodeHash, onEthereum.bytecodeHash);
  });
});

test('engine auditContract: invalid address => INVALID_ADDRESS (no RPC call)', async function () {
  let called = false;
  await withFetch(function () { called = true; return null; }, async function () {
    const r = await Engine.auditContract({ address: '0x123', networkId: 'ethereum' });
    assert.equal(r.contractType, 'INVALID_ADDRESS');
    assert.equal(r.bytecodeAvailable, false);
    assert.equal(r.analysisCompleteness, 'LIMITED');
  });
  assert.equal(called, false, 'no RPC request should be made for an invalid address');
});

test('engine auditContract: wrong chain => NETWORK_CHAIN_ID_MISMATCH', async function () {
  await withFetch(function (url, method) {
    if (method === 'eth_chainId') return '0x2';
    return null;
  }, async function () {
    const r = await Engine.auditContract({ address: ADDR, networkId: 'ethereum' });
    assert.equal(r.contractType, 'NETWORK_CHAIN_ID_MISMATCH');
    assert.equal(r.bytecodeAvailable, false);
  });
});

// ── Result metadata + payload ────────────────────────────────────────────────

test('analyze propagates network identity into the result and payload', function () {
  const r = Engine.analyze('6000f3', {
    address: ADDR,
    networkId: 'genlayerStudionet',
    networkName: 'GenLayer Studionet',
    chainId: 61999
  });
  assert.equal(r.networkId, 'genlayerStudionet');
  assert.equal(r.networkName, 'GenLayer Studionet');
  assert.equal(r.chainId, 61999);
  assert.equal(r.contractType, 'CONTRACT');
  assert.equal(r.bytecodeAvailable, true);
  assert.equal(r.analysisCompleteness, 'COMPLETE');

  const p = r.payload;
  assert.equal(p.network, 'genlayerStudionet');
  assert.equal(p.networkName, 'GenLayer Studionet');
  assert.equal(p.chainId, 61999);
  assert.equal(p.contract.chainId, 61999);
  assert.equal(p.contract.bytecodeHash, r.bytecodeHash);
  assert.equal(p.analysisVersion, '8.1.0');
});

test('LIMITED analysis result separates completeness from score (never "safe")', function () {
  const r = Engine.analyze('', { address: ADDR, networkId: 'ethereum', chainId: 1 });
  assert.equal(r.analysisCompleteness, 'LIMITED');
  assert.equal(r.bytecodeAvailable, false);
  assert.equal(r.risk.level, 'LIMITED ANALYSIS');
  assert.notEqual(r.risk.level, 'LOW RISK');
  assert.notEqual(r.risk.level, 'SAFE');
});

console.log('\nAll audit-networks tests completed.');
