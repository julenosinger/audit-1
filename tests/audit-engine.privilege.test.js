'use strict';
// Phase 6 tests: Privileged Operations & Access Control Analyzer.
// Run with:  node tests/audit-engine.privilege.test.js
const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../public/audit-engine.js');

function push4(sel) { return '63' + sel; }

// A minimal single-selector dispatcher whose function entry (JUMPDEST) sits at
// pc 14:  PUSH1 0 CALLDATALOAD, PUSH4 <sel>, EQ, PUSH2 0x000e, JUMPI, STOP, JUMPDEST.
function dispatcher(sel, body) {
  return '60003563' + sel + '14' + '61' + '000e' + '57' + '00' + '5b' + body;
}

// mint body with a CALLER gate dominating an SSTORE (state write is gated).
const MINT_SEL = '40c10f19';
const MINT_GATED = dispatcher(MINT_SEL, '33600114601757005b55');
// mint body with no gate at all (writes slot 0 directly).
const MINT_UNRESTRICTED = dispatcher(MINT_SEL, '600060015500');

function ops(r) { return r.privilegedOperations || []; }
function opFor(r, operation) { return ops(r).filter(function (o) { return o.operation === operation; }); }

// ── Catalog detection ────────────────────────────────────────────────────────

test('mint selector (unresolved) => MINT operation, UNKNOWN access', function () {
  var r = Engine.analyze(push4(MINT_SEL));
  var m = opFor(r, 'MINT')[0];
  assert.ok(m, 'mint privilege op present');
  assert.equal(m.reachability, 'UNRESOLVED');
  assert.equal(m.accessControl, 'UNKNOWN');
  assert.equal(r.accessControlSummary.privilegedFunctions, 1);
});

test('ownership: transferOwnership + renounceOwnership => detected, owner UNKNOWN', function () {
  var r = Engine.analyze(push4('f2fde38b') + push4('715018a6') + push4('8da5cb5b'));
  assert.equal(r.accessControlSummary.ownership, 'Detected');
  assert.ok(opFor(r, 'TRANSFER_OWNERSHIP').length >= 1);
  assert.ok(opFor(r, 'RENOUNCE_OWNERSHIP').length >= 1);
  // No fabricated owner address.
  opFor(r, 'TRANSFER_OWNERSHIP').forEach(function (o) { assert.equal(o.accessControl, 'UNKNOWN'); });
});

test('AccessControl: grantRole/revokeRole/hasRole => roles detected, specific roles UNKNOWN', function () {
  var r = Engine.analyze(push4('2f2ff15d') + push4('d547741f') + push4('91d14854'));
  assert.equal(r.accessControlSummary.roleBased, 'Detected');
  assert.ok(opFor(r, 'GRANT_ROLE').length >= 1);
  assert.ok(opFor(r, 'REVOKE_ROLE').length >= 1);
  // Selector proves the signature, not which concrete roles exist.
  var gl = opFor(r, 'GRANT_ROLE')[0];
  assert.equal(gl.accessControl, 'UNKNOWN');
});

test('pause/unpause => PAUSE + UNPAUSE operations', function () {
  var r = Engine.analyze(push4('8456cb59') + push4('3f4ba83a'));
  assert.ok(opFor(r, 'PAUSE').length >= 1);
  assert.ok(opFor(r, 'UNPAUSE').length >= 1);
});

test('burn => BURN operation', function () {
  var r = Engine.analyze(push4('42966c68') + push4('79cc6790'));
  var b = opFor(r, 'BURN');
  assert.ok(b.length >= 1);
});

test('upgrade selectors => UPGRADE_IMPLEMENTATION operation', function () {
  var r = Engine.analyze(push4('3659cfe6') + push4('4f1ef286'));
  assert.ok(opFor(r, 'UPGRADE_IMPLEMENTATION').length >= 1);
});

test('ABI drives blacklist/fee detection (no selectors needed)', function () {
  var r = Engine.analyze('5b', { abi: [
    { type: 'function', name: 'setBuyTax', inputs: [] },
    { type: 'function', name: 'setBlacklist', inputs: [] }
  ] });
  assert.ok(opFor(r, 'SET_FEE').length >= 1);
  assert.ok(opFor(r, 'BLACKLIST').length >= 1);
});

// ── Authorization classification ─────────────────────────────────────────────

test('resolved mint with CALLER gate dominating state write => CONFIRMED_RESTRICTED', function () {
  var r = Engine.analyze(MINT_GATED);
  var m = opFor(r, 'MINT')[0];
  assert.ok(m, 'mint op present');
  assert.equal(m.functionId, 'fn_0');
  assert.equal(m.reachability, 'REACHABLE');
  assert.equal(m.accessControl, 'CONFIRMED_RESTRICTED');
  assert.equal(m.authorization.confidence, 'HIGH');
  assert.ok(m.storageWrites >= 1, 'state write recorded');
});

test('resolved mint with no detectable gate => UNKNOWN (never asserted unrestricted)', function () {
  var r = Engine.analyze(MINT_UNRESTRICTED);
  var m = opFor(r, 'MINT')[0];
  assert.equal(m.accessControl, 'UNKNOWN');
  assert.equal(m.authorization.confidence, 'LOW');
});

// ── Capability ≠ vulnerability ───────────────────────────────────────────────

test('mint capability is NEVER auto-escalated to HIGH/CRITICAL', function () {
  var r = Engine.analyze(push4(MINT_SEL));
  var sev = (r.findings || []).map(function (f) { return f.severity; });
  assert.ok(sev.indexOf('CRITICAL') === -1);
  assert.ok(sev.indexOf('HIGH') === -1);
});

test('privileged-operations summary finding is INFO (does not move risk)', function () {
  var r = Engine.analyze(MINT_GATED);
  var f = r.findings.filter(function (x) { return x.id === 'privileged-operations-summary'; })[0];
  assert.ok(f, 'summary finding present');
  assert.equal(f.severity, 'INFO');
  assert.equal(f.scoreImpact, 0);
});

// ── False positives ──────────────────────────────────────────────────────────

test('dead/unreachable mint selector is NOT detected as a privileged op', function () {
  var r = Engine.analyze('00' + push4(MINT_SEL)); // STOP then PUSH4 (dead)
  assert.equal(ops(r).length, 0);
  assert.equal(r.accessControlSummary.privilegedFunctions, 0);
});

test('CALLER gate with no privileged selector => no privileged ops', function () {
  var r = Engine.analyze('33600114600857005b55'); // gate only
  assert.equal(ops(r).length, 0);
});

test('benign bytecode => no privileged ops, summary zero', function () {
  var r = Engine.analyze('5b'.repeat(300));
  assert.equal(ops(r).length, 0);
  assert.equal(r.accessControlSummary.privilegedFunctions, 0);
});

// ── Evidence graph + payload integration ─────────────────────────────────────

test('evidence graph contains PRIVILEGED_OPERATION + AUTHORIZATION_GATE nodes', function () {
  var r = Engine.analyze(MINT_GATED);
  var types = (r.evidenceGraph.nodes || []).map(function (n) { return n.type; });
  assert.ok(types.indexOf('PRIVILEGED_OPERATION') !== -1, 'privileged op node present');
  assert.ok(types.indexOf('AUTHORIZATION_GATE') !== -1, 'authorization gate node present');
  assert.ok(r.privilegeGraph && r.privilegeGraph.nodes.length >= 1);
});

test('payload carries privilegedOperations + accessControlSummary + privilegeGraph', function () {
  var r = Engine.analyze(MINT_GATED);
  assert.ok(r.payload.analysis.privilegedOperations, 'privilegedOperations in payload');
  assert.ok(r.payload.analysis.accessControlSummary, 'accessControlSummary in payload');
  assert.ok(r.payload.analysis.privilegeGraph, 'privilegeGraph in payload');
  assert.equal(r.payload.version, '8.1.0');
});

// ── Determinism / version ────────────────────────────────────────────────────

test('identical bytecode + analyzer version => deterministic privilege evidence', function () {
  var a = Engine.analyze(MINT_GATED);
  var b = Engine.analyze(MINT_GATED);
  assert.equal(a.bytecodeHash, b.bytecodeHash);
  assert.deepEqual(a.accessControlSummary, b.accessControlSummary);
  assert.equal(a.analysisVersion, '8.1.0');
});

console.log('\nAll privilege tests completed.');
