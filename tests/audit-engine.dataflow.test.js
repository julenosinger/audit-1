'use strict';
// Phase 4 tests: Data-Flow Analysis + security semantics.
// Run with:  node tests/audit-engine.dataflow.test.js
const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../public/audit-engine.js');

function ins(op, arg, pc) { return { opcode: op, argument: arg || '', pc: pc || 0, block: 0, reach: 'REACHABLE' }; }
function hasFinding(result, id) { return result.findings.some(function (f) { return f.id === id; }); }

// ── Value provenance ─────────────────────────────────────────────────────────
test('dataflow: PUSH value carries source PUSH + const', function () {
  var s = Engine.execBlockStackDF([ins('PUSH1', '05')]);
  assert.equal(s[0].k, 'const');
  assert.equal(s[0].source, 'PUSH');
  assert.equal(Number(s[0].v), 5);
});

test('dataflow: PUSH → ADD preserves provenance (DERIVED)', function () {
  var s = Engine.execBlockStackDF([ins('PUSH1', '05', 0), ins('PUSH1', '03', 2), ins('ADD', '', 4)]);
  var top = s[s.length - 1];
  assert.equal(top.k, 'const');
  assert.equal(top.source, 'DERIVED');
  assert.equal(Number(top.v), 8);
  assert.equal(top.deps.length, 3); // both operands + result
});

test('dataflow: CALLER → EQ records comparison with CALLER source', function () {
  var ev = { comparisons: [], storageReads: [], storageWrites: [], externalCalls: [], events: [], values: 0 };
  Engine.execBlockStackDF([ins('CALLER', '', 0), ins('PUSH20', 'aa'.repeat(20), 1), ins('EQ', '', 22)], ev);
  assert.equal(ev.comparisons.length, 1);
  assert.equal(ev.comparisons[0].right.source, 'CALLER');
  assert.equal(ev.comparisons[0].left.source, 'PUSH');
});

test('dataflow: unsupported opcode propagates UNKNOWN (never guesses)', function () {
  var s = Engine.execBlockStackDF([ins('PUSH1', '05', 0), ins('CALLDATALOAD', '', 2), ins('PUSH1', '03', 3), ins('ADD', '', 5)]);
  assert.equal(s[s.length - 1].k, 'unknown');
});

// ── Storage tracking ─────────────────────────────────────────────────────────
test('dataflow: SLOAD tracked with known slot', function () {
  var r = Engine.analyze('600054'); // PUSH1 0 SLOAD
  assert.equal(r.dataFlow.storageReads.length, 1);
  assert.equal(r.dataFlow.storageReads[0].slot, '0x0');
});

test('dataflow: SSTORE tracked with known slot + value', function () {
  var r = Engine.analyze('6000600155'); // PUSH1 0 PUSH1 1 SSTORE
  assert.equal(r.dataFlow.storageWrites.length, 1);
  assert.equal(r.dataFlow.storageWrites[0].slot, '0x0');
  assert.equal(r.dataFlow.storageWrites[0].value, '0x1');
});

test('dataflow: unknown storage slot (CALLER SLOAD) is UNKNOWN', function () {
  var r = Engine.analyze('3354'); // CALLER SLOAD
  assert.equal(r.dataFlow.storageReads[0].slot, 'UNKNOWN');
});

test('dataflow: external CALL tracked (target UNKNOWN)', function () {
  var r = Engine.analyze('f1');
  assert.equal(r.dataFlow.externalCalls.length, 1);
  assert.equal(r.dataFlow.externalCalls[0].opcode, 'CALL');
  assert.equal(r.dataFlow.externalCalls[0].target, 'UNKNOWN');
});

// ── Reentrancy / CEI ─────────────────────────────────────────────────────────
test('reentrancy: CALL alone => NONE (no state interaction)', function () {
  var r = Engine.analyze('f1');
  assert.equal(r.dataFlow.reentrancy.classification, 'NONE');
  assert.ok(!hasFinding(r, 'reentrancy-pattern'));
});

test('reentrancy: SSTORE unrelated to CALL => NONE', function () {
  var r = Engine.analyze('6000600155'); // only a write
  assert.equal(r.dataFlow.reentrancy.classification, 'NONE');
});

test('reentrancy: SLOAD → CALL → SSTORE same slot => LIKELY (never CONFIRMED)', function () {
  var r = Engine.analyze('600054f16000600155'); // read slot0, CALL, write slot0
  assert.equal(r.dataFlow.reentrancy.classification, 'LIKELY');
  assert.ok(hasFinding(r, 'reentrancy-pattern'));
  var f = r.findings.filter(function (x) { return x.id === 'reentrancy-pattern'; })[0];
  assert.equal(f.severity, 'MEDIUM');
  assert.ok(f.dataFlowEvidence.length > 0);
});

test('reentrancy: CALL → SSTORE (no read dependency) => POTENTIAL', function () {
  var r = Engine.analyze('f16000600155');
  assert.equal(r.dataFlow.reentrancy.classification, 'POTENTIAL');
  assert.ok(hasFinding(r, 'reentrancy-pattern'));
});

test('CEI: SSTORE → CALL is effects-before-interactions (no reentrancy signal)', function () {
  var r = Engine.analyze('6000600155f1');
  assert.equal(r.dataFlow.reentrancy.classification, 'NONE');
  assert.ok(r.dataFlow.cei.effectsBeforeInteractions >= 1);
});

test('reentrancy guard: lock → CALL → unlock detected', function () {
  var r = Engine.analyze('6000600155f16000600055');
  assert.equal(r.dataFlow.reentrancyGuard.detected, true);
  assert.ok(hasFinding(r, 'reentrancy-guard'));
});

// ── Control dependency / access control ──────────────────────────────────────
test('control dependency: CALLER EQ → JUMPI → SSTORE is gated', function () {
  var code = '33600114600857005b55'; // CALLER, PUSH1 1, EQ, PUSH1 8, JUMPI, STOP, JUMPDEST, SSTORE
  var r = Engine.analyze(code);
  assert.ok(r.dataFlow.accessControl.length >= 1, 'access control detected');
  assert.equal(r.dataFlow.accessControl[0].protectedBy[0].source, 'CALLER');
  assert.ok(r.dataFlow.controlDependencies.length >= 1, 'control dependency recorded');
  assert.ok(hasFinding(r, 'access-control-gate'));
});

test('CALLER alone (no conditional) => no access control finding', function () {
  var r = Engine.analyze('33');
  assert.equal(r.dataFlow.accessControl.length, 0);
  assert.ok(!hasFinding(r, 'access-control-gate'));
});

// ── Reachability 3-way ───────────────────────────────────────────────────────
test('reachability: REACHABLE / MAYBE_REACHABLE / UNREACHABLE', function () {
  assert.equal(Engine.analyze('ff').findings.some(function (f) { return f.id === 'selfdestruct-present'; }), true);
  // STOP then SELFDESTRUCT => UNREACHABLE
  var unreachable = Engine.analyze('00ff');
  assert.ok(!hasFinding(unreachable, 'selfdestruct-present'));
  assert.ok(hasFinding(unreachable, 'unreachable-code'));
  // dynamic JUMP then JUMPDEST+SELFDESTRUCT => MAYBE_REACHABLE
  var maybe = Engine.analyze('565bff');
  assert.ok(hasFinding(maybe, 'selfdestruct-maybe'));
  assert.ok(!hasFinding(maybe, 'selfdestruct-present'));
});

test('buildCfg exposes maybeReachableInstructions', function () {
  var c = Engine.buildCfg(Engine.disassemble('565bff').instructions);
  assert.equal(c.stats.maybeReachableInstructions, 2); // JUMPDEST + SELFDESTRUCT
});

// ── Finding engine V4 fields ─────────────────────────────────────────────────
test('findings carry dataFlowEvidence / controlFlowEvidence', function () {
  var r = Engine.analyze('600054f16000600155');
  var f = r.findings.filter(function (x) { return x.id === 'reentrancy-pattern'; })[0];
  assert.ok(Array.isArray(f.dataFlowEvidence));
  assert.ok(Array.isArray(f.controlFlowEvidence));
});

console.log('\nAll data-flow tests completed.');
