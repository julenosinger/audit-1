'use strict';
// Phase 7 tests: Proxy & Upgradeability Intelligence.
// Run with:  node tests/audit-proxy.test.js
const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../public/audit-engine.js');

const IMPL_SLOT = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';
const BEACON_SLOT = 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const UPGRADE_TO = '3659cfe6';
const UPGRADE_TO_AND_CALL = '4f1ef286';
const CHANGE_ADMIN = '8f283970';
const PROXIABLE_UUID = '52d1902d';
const IMPLEMENTATION_FN = '5c60da1b';
const ADMIN_FN = 'f851a440';

// EIP-1167 canonical minimal proxy runtime (prefix + 20-byte impl + suffix).
const EIP1167_PREFIX = '363d3d373d3d3d363d73';
const EIP1167_SUFFIX = '5af43d82803e903d91602b57fd5bf3';

function push4(sel) { return '63' + sel; }
function push20(addr) { return '73' + addr; }
function push32(hex) { return '7f' + hex; }

function minimalProxy(impl) {
  return EIP1167_PREFIX + impl + EIP1167_SUFFIX;
}

function proxyFor(r) { return r.proxyAnalysis || r.upgradeability || null; }

// ── Proxy type classification ────────────────────────────────────────────────

test('EIP-1967: DELEGATECALL + implementation slot => EIP-1967 CONFIRMED', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT));
  var p = proxyFor(r);
  assert.ok(p);
  assert.equal(p.detected, true);
  assert.equal(p.proxyType, 'EIP-1967');
  assert.equal(p.confidence, 'CONFIRMED');
  assert.equal(p.hasImplementationSlot, true);
});

test('Transparent proxy: DELEGATECALL + impl slot + admin slot => TRANSPARENT CONFIRMED', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT) + push32(ADMIN_SLOT));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'TRANSPARENT');
  assert.equal(p.confidence, 'CONFIRMED');
  assert.equal(p.admin.confidence, 'INFERRED');
});

test('UUPS: impl slot + proxiableUUID => UUPS CONFIRMED', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT) + push4(PROXIABLE_UUID));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'UUPS');
  assert.equal(p.confidence, 'CONFIRMED');
  assert.equal(p.proxiableUUID, true);
});

test('UUPS: impl slot + upgradeTo (no proxiableUUID) => UUPS LIKELY', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT) + push4(UPGRADE_TO));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'UUPS');
  assert.equal(p.confidence, 'LIKELY');
});

test('Beacon proxy: beacon slot => BEACON', function () {
  var r = Engine.analyze('f4' + push32(BEACON_SLOT));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'BEACON');
  assert.equal(p.hasBeaconSlot, true);
});

test('Minimal proxy (EIP-1167): extract embedded implementation CONFIRMED', function () {
  var impl = 'ab'.repeat(20);
  var r = Engine.analyze(minimalProxy(impl));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'MINIMAL_PROXY');
  assert.equal(p.confidence, 'CONFIRMED');
  assert.equal(p.implementation.address, '0x' + impl);
  assert.equal(p.implementation.confidence, 'CONFIRMED');
});

test('detectMinimalProxy extracts address and rejects malformed', function () {
  var ok = Engine.detectMinimalProxy(minimalProxy('cd'.repeat(20)));
  assert.equal(ok.implementation, '0x' + 'cd'.repeat(20));
  assert.equal(ok.confidence, 'CONFIRMED');
  assert.equal(Engine.detectMinimalProxy('6000f3'), null);
  assert.equal(Engine.detectMinimalProxy(''), null);
});

test('Custom proxy: DELEGATECALL + hardcoded PUSH20 => CUSTOM LIKELY', function () {
  var r = Engine.analyze('f4' + push20('ab'.repeat(20)));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'CUSTOM');
  assert.equal(p.confidence, 'LIKELY');
  assert.equal(p.implementation.address, '0x' + 'ab'.repeat(20));
});

test('Custom proxy: DELEGATECALL alone => CUSTOM UNKNOWN (never forced into a standard)', function () {
  var r = Engine.analyze('f4');
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'CUSTOM');
  assert.equal(p.confidence, 'UNKNOWN');
  assert.equal(p.implementation.address, null);
});

test('non-proxy contract (no DELEGATECALL) => NONE', function () {
  var r = Engine.analyze('6000f3');
  var p = proxyFor(r);
  assert.equal(p.detected, false);
  assert.equal(p.proxyType, 'NONE');
});

test('DELEGATECALL alone is NOT a HIGH/CRITICAL finding', function () {
  var r = Engine.analyze('f4');
  var sevs = r.findings.map(function (f) { return f.severity; });
  assert.ok(sevs.indexOf('HIGH') === -1);
  assert.ok(sevs.indexOf('CRITICAL') === -1);
});

// ── Delegatecall reachability / contextualization ────────────────────────────

test('delegatecall reachability: reachable vs unreachable contextualized', function () {
  var reachable = Engine.analyze('f4');
  assert.equal(proxyFor(reachable).delegatecall[0].reach, 'REACHABLE');

  var unreachable = Engine.analyze('00f4'); // STOP ; DELEGATECALL (dead)
  var d = proxyFor(unreachable).delegatecall[0];
  assert.equal(d.reach, 'UNREACHABLE');
});

// ── Implementation / admin detection ─────────────────────────────────────────

test('implementation detection: EIP-1967 slot => INFERRED (address not fabricated)', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT));
  var p = proxyFor(r);
  assert.equal(p.implementation.address, null);
  assert.equal(p.implementation.confidence, 'INFERRED');
  assert.ok(p.implementation.source.indexOf('implementation slot') !== -1);
});

test('admin detection: admin slot => INFERRED (address not fabricated)', function () {
  var r = Engine.analyze('f4' + push32(ADMIN_SLOT));
  var p = proxyFor(r);
  assert.equal(p.admin.address, null);
  assert.equal(p.admin.confidence, 'INFERRED');
});

// ── Upgrade functions + authorization ────────────────────────────────────────

test('upgrade selectors detected as upgrade functions (UNKNOWN when unresolved)', function () {
  var r = Engine.analyze(push4(UPGRADE_TO) + push4(UPGRADE_TO_AND_CALL) + push4(CHANGE_ADMIN));
  var p = proxyFor(r);
  var names = p.upgradeFunctions.map(function (u) { return u.function; });
  assert.ok(names.indexOf('upgradeTo(address)') !== -1);
  assert.ok(names.indexOf('upgradeToAndCall(address,bytes)') !== -1);
  assert.ok(names.indexOf('changeAdmin(address)') !== -1);
  p.upgradeFunctions.forEach(function (u) { assert.equal(u.accessControl, 'UNKNOWN'); });
});

test('upgrade authorization: CONFIRMED_RESTRICTED when CALLER gate dominates a state write', function () {
  var fg = {
    blockFn: { '0': 'fn_0', '1': 'fn_0', '2': 'fn_0' },
    entryToId: { '10': 'fn_0' }
  };
  var df = {
    controlDependencies: [{ blockId: 1, gatedBy: 'CALLER EQ 0x1' }],
    comparisons: [{ blockId: 1, left: { source: 'CALLER' }, right: { source: 'PUSH' } }],
    storageWrites: [{ blockId: 1, slot: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc' }]
  };
  var a = Engine.classifyUpgradeAuthorization('fn_0', fg, df);
  assert.equal(a.status, 'CONFIRMED_RESTRICTED');
  assert.equal(a.confidence, 'HIGH');
});

test('upgrade authorization: gated but no state write => LIKELY_RESTRICTED', function () {
  var fg = { blockFn: { '0': 'fn_0' }, entryToId: {} };
  var df = {
    controlDependencies: [{ blockId: 0, gatedBy: 'CALLER EQ 0x1' }],
    comparisons: [{ blockId: 0, left: { source: 'CALLER' }, right: { source: 'PUSH' } }],
    storageWrites: []
  };
  var a = Engine.classifyUpgradeAuthorization('fn_0', fg, df);
  assert.equal(a.status, 'LIKELY_RESTRICTED');
});

test('upgrade authorization: CALLER comparison only => INFERRED_RESTRICTED', function () {
  var fg = { blockFn: { '0': 'fn_0' }, entryToId: {} };
  var df = {
    controlDependencies: [],
    comparisons: [{ blockId: 0, left: { source: 'CALLER' }, right: { source: 'PUSH' } }],
    storageWrites: []
  };
  var a = Engine.classifyUpgradeAuthorization('fn_0', fg, df);
  assert.equal(a.status, 'INFERRED_RESTRICTED');
});

test('upgrade authorization: no evidence => UNKNOWN (never "unrestricted")', function () {
  var fg = { blockFn: { '0': 'fn_0' }, entryToId: {} };
  var a = Engine.classifyUpgradeAuthorization('fn_0', fg, { controlDependencies: [], comparisons: [], storageWrites: [] });
  assert.equal(a.status, 'UNKNOWN');
  assert.notEqual(a.status, 'POSSIBLY_UNRESTRICTED');
});

// ── Findings / risk ──────────────────────────────────────────────────────────

test('upgrade authorization UNKNOWN => MEDIUM at most (never HIGH/CRITICAL)', function () {
  var r = Engine.analyze(push4(UPGRADE_TO));
  var f = r.findings.filter(function (x) { return x.id === 'upgrade-authorization-unknown'; })[0];
  assert.ok(f, 'unknown authorization finding present');
  assert.equal(f.severity, 'MEDIUM');
  var sevs = r.findings.map(function (x) { return x.severity; });
  assert.ok(sevs.indexOf('CRITICAL') === -1);
  assert.ok(sevs.indexOf('HIGH') === -1);
});

test('proxy detection is informational (INFO)', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT));
  var f = r.findings.filter(function (x) { return x.id === 'proxy-detected-v2'; })[0];
  assert.ok(f);
  assert.equal(f.severity, 'INFO');
});

// ── Evidence graph / payload ─────────────────────────────────────────────────

test('evidence graph contains PROXY and IMPLEMENTATION nodes', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT));
  var types = r.evidenceGraph.nodes.map(function (n) { return n.type; });
  assert.ok(types.indexOf('PROXY') !== -1);
  assert.ok(types.indexOf('IMPLEMENTATION') !== -1);
  var edges = r.evidenceGraph.edges.map(function (e) { return e.type; });
  assert.ok(edges.indexOf('IMPLEMENTS') !== -1);
});

test('payload carries proxy/upgradeability evidence', function () {
  var r = Engine.analyze('f4' + push32(IMPL_SLOT) + push4(UPGRADE_TO));
  var p = r.payload;
  assert.ok(p.analysis.proxyAnalysis);
  assert.ok(p.analysis.upgradeability);
  assert.ok(p.analysis.implementationEvidence);
  assert.ok(p.analysis.adminEvidence);
  assert.ok(p.analysis.upgradeFunctions);
  assert.ok(p.analysis.upgradeAuthorization);
  assert.ok(p.analysis.delegatecallEvidence);
  assert.ok(p.analysis.proxyStorageEvidence);
  assert.equal(p.version, '8.1.0');
});

// ── Limits / honesty ─────────────────────────────────────────────────────────

test('dynamic jump does not fabricate an implementation address', function () {
  var r = Engine.analyze('56' + push4(UPGRADE_TO)); // dynamic jump + upgrade selector
  var p = proxyFor(r);
  assert.equal(p.implementation.address, null);
});

test('benign bytecode => NONE proxy, no upgrade functions', function () {
  var r = Engine.analyze('5b'.repeat(300));
  var p = proxyFor(r);
  assert.equal(p.proxyType, 'NONE');
  assert.equal(p.upgradeFunctions.length, 0);
});

// ── Phase 7.1: proxy false-positive fix ──────────────────────────────────────

test('isPlausibleContractAddress rejects zero / all-FF / malformed', function () {
  assert.equal(Engine.isPlausibleContractAddress('0x' + '0'.repeat(40)), false);
  assert.equal(Engine.isPlausibleContractAddress('0x' + 'f'.repeat(40)), false);
  assert.equal(Engine.isPlausibleContractAddress('0x123'), false);
  assert.equal(Engine.isPlausibleContractAddress('0x' + 'ab'.repeat(20)), true);
  assert.equal(Engine.isPlausibleContractAddress(null), false);
});

test('PUSH20 all-FF is NOT reported as an implementation address', function () {
  var r = Engine.analyze('f4' + push20('f'.repeat(40)));
  var p = proxyFor(r);
  assert.equal(p.implementation.address, null, '0xffff…ffff must never be an implementation');
  var f = r.findings.filter(function (x) { return x.id === 'implementation-changeable'; });
  assert.equal(f.length, 0, 'no implementation finding for sentinel address');
});

test('PUSH20 zero address is NOT reported as an implementation address', function () {
  var r = Engine.analyze('f4' + push20('0'.repeat(40)));
  var p = proxyFor(r);
  assert.equal(p.implementation.address, null);
});

test('random PUSH20 without DELEGATECALL is NOT implementation evidence', function () {
  var r = Engine.analyze(push20('ab'.repeat(20)));
  var p = proxyFor(r);
  assert.equal(p.implementation.address, null, 'bare PUSH20 must not become implementation');
  var f = r.findings.filter(function (x) { return x.id === 'implementation-changeable'; });
  assert.equal(f.length, 0);
});

test('PUSH20 + DELEGATECALL => weak (INFERRED) implementation, not CONFIRMED', function () {
  var r = Engine.analyze('f4' + push20('ab'.repeat(20)));
  var p = proxyFor(r);
  assert.equal(p.implementation.address, '0x' + 'ab'.repeat(20));
  assert.equal(p.implementation.confidence, 'INFERRED');
  assert.notEqual(p.implementation.confidence, 'CONFIRMED');
});

test('valid EIP-1967 / EIP-1167 still produce implementation evidence', function () {
  var e1967 = Engine.analyze('f4' + push32(IMPL_SLOT));
  assert.ok(proxyFor(e1967).implementation.source.indexOf('implementation slot') !== -1);

  var e1167 = Engine.analyze(minimalProxy('cd'.repeat(20)));
  assert.equal(proxyFor(e1167).implementation.confidence, 'CONFIRMED');
});

console.log('\nAll audit-proxy tests completed.');
