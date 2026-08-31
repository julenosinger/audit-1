'use strict';
// Phase 3 tests: Control Flow Analysis, stack, selectors, reachability, proxy V2.
// Run with:  node tests/audit-engine.cfg.test.js
const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../public/audit-engine.js');

const IMPL_SLOT = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';

function push1(byte) { return '60' + byte; }
function push4(sel) { return '63' + sel; }
function push20(addr) { return '73' + addr; }
function push32(hex) { return '7f' + hex; }

function cfg(code) {
  return Engine.buildCfg(Engine.disassemble(code).instructions);
}

function hasFinding(result, id) {
  return result.findings.some(function (f) { return f.id === id; });
}

// ── Disassembler ─────────────────────────────────────────────────────────────
test('disassemble: PUSH1 / PUSH32 / truncated PUSH / invalid / empty', function () {
  assert.equal(Engine.disassemble('6005').instructions[0].opcode, 'PUSH1');
  assert.equal(Engine.disassemble('7f' + 'ab'.repeat(32)).instructions[0].opcode, 'PUSH32');
  // Truncated PUSH32 at EOF (only 3 bytes available)
  var t = Engine.disassemble('7fabcd');
  assert.equal(t.instructions[0].opcode, 'PUSH32');
  assert.equal(t.instructions[0].truncated, true);
  assert.equal(Engine.disassemble('zz').valid, false);
  assert.equal(Engine.disassemble('').instructions.length, 0);
});

// ── CFG: terminators / blocks / edges ────────────────────────────────────────
test('CFG: STOP / RETURN / REVERT terminate a block with no successors', function () {
  ['00', 'f3', 'fd'].forEach(function (op) {
    var c = cfg(op);
    assert.equal(c.blocks.length, 1);
    assert.equal(c.blocks[0].successors.length, 0);
  });
});

test('CFG: static JUMP resolves to JUMPDEST target', function () {
  var c = cfg('6003565b00'); // PUSH1 3 JUMP ; JUMPDEST ; STOP
  assert.equal(c.stats.staticJumps, 1);
  assert.equal(c.stats.dynamicJumps, 0);
  assert.equal(c.blocks[0].jumpTargetPc, 3);
  assert.ok(c.blocks[0].successors.length >= 1);
  // every block reachable
  c.blocks.forEach(function (b) { assert.equal(b.reachable, true); });
});

test('CFG: JUMPI produces two edges (true + false)', function () {
  var c = cfg('6001600657005b00'); // PUSH1 1 PUSH1 6 JUMPI ; STOP ; JUMPDEST ; STOP
  assert.equal(c.stats.staticJumps, 1);
  var b0 = c.blocks[0];
  assert.equal(b0.terminator, 'JUMPI');
  assert.equal(b0.successors.length, 2);
});

test('CFG: loop (self edge) is detected', function () {
  var c = cfg('5b600060005700'); // JUMPDEST ; PUSH1 0 PUSH1 0 JUMPI(->0) ; STOP
  var b0 = c.blocks[0];
  assert.ok(b0.successors.indexOf(0) !== -1, 'block 0 has a self-loop');
});

test('CFG: dynamic jump (no static target) is marked dynamic', function () {
  var c = cfg('56'); // JUMP with empty stack
  assert.equal(c.stats.dynamicJumps, 1);
  assert.equal(c.blocks[0].dynamicJump, true);
});

test('CFG: multiple branches (fallthrough + jump) all reachable', function () {
  var c = cfg('6001600657005b00');
  assert.equal(c.blocks.length, 3);
  assert.ok(c.blocks.every(function (b) { return b.reachable; }));
});

// ── Reachability ─────────────────────────────────────────────────────────────
test('reachable SELFDESTRUCT is reported; unreachable SELFDESTRUCT is dead code', function () {
  var reachable = Engine.analyze('ff');
  assert.ok(hasFinding(reachable, 'selfdestruct-present'));
  assert.ok(!hasFinding(reachable, 'unreachable-code'));

  var unreachable = Engine.analyze('00ff'); // STOP ; SELFDESTRUCT
  assert.ok(!hasFinding(unreachable, 'selfdestruct-present'));
  assert.ok(hasFinding(unreachable, 'unreachable-code'));
});

test('reachable DELEGATECALL => proxy; unreachable DELEGATECALL => not a proxy', function () {
  var reachable = Engine.analyze('f4');
  assert.equal(reachable.capabilities.proxy.detected, true);

  var unreachable = Engine.analyze('00f4');
  assert.equal(unreachable.capabilities.proxy.detected, false);
  assert.ok(hasFinding(unreachable, 'unreachable-code'));
});

// ── Selector analysis / function map ─────────────────────────────────────────
test('CALLDATALOAD PUSH4 EQ JUMPI resolves a known selector with entry pc', function () {
  var code = '356370a0823114600b57005b00'; // balanceOf dispatcher
  var r = Engine.analyze(code);
  var fm = r.functionMap['70a08231'];
  assert.ok(fm, 'function map contains balanceOf');
  assert.equal(fm.name, 'balanceOf(address)');
  assert.equal(fm.confidence, 'HIGH');
  assert.equal(fm.entryPc, 11);
});

test('unknown selector is named UNKNOWN (never invented)', function () {
  var code = '3563deadbeef14600b57005b00';
  var r = Engine.analyze(code);
  var fm = r.functionMap['deadbeef'];
  assert.ok(fm);
  assert.equal(fm.name, 'UNKNOWN');
});

// ── Stack analysis ───────────────────────────────────────────────────────────
function ins(op, arg) { return { opcode: op, argument: arg || '' }; }

test('stack: PUSH + ADD', function () {
  var s = Engine.execBlockStack([ins('PUSH1', '05'), ins('PUSH1', '03'), ins('ADD')]);
  assert.equal(Number(s[s.length - 1].v), 8);
});

test('stack: PUSH + SUB (operand order)', function () {
  var s = Engine.execBlockStack([ins('PUSH1', '05'), ins('PUSH1', '03'), ins('SUB')]);
  assert.equal(Number(s[s.length - 1].v), 2); // 5 - 3
});

test('stack: EQ and ISZERO', function () {
  assert.equal(Number(Engine.execBlockStack([ins('PUSH1', '05'), ins('PUSH1', '05'), ins('EQ')]).pop().v), 1);
  assert.equal(Number(Engine.execBlockStack([ins('PUSH1', '00'), ins('ISZERO')]).pop().v), 1);
});

test('stack: DUP / SWAP / POP', function () {
  var dup = Engine.execBlockStack([ins('PUSH1', '07'), ins('DUP1')]);
  assert.equal(Number(dup[0].v), 7); assert.equal(Number(dup[1].v), 7);

  var swap = Engine.execBlockStack([ins('PUSH1', '01'), ins('PUSH1', '02'), ins('SWAP1')]);
  assert.equal(Number(swap[swap.length - 1].v), 1);

  var pop = Engine.execBlockStack([ins('PUSH1', '01'), ins('PUSH1', '02'), ins('POP')]);
  assert.equal(Number(pop[pop.length - 1].v), 1);
});

test('stack: unsupported opcode invalidates (never guesses)', function () {
  var s = Engine.execBlockStack([ins('PUSH1', '05'), ins('CALLDATALOAD'), ins('PUSH1', '03'), ins('ADD')]);
  // CALLDATALOAD is unsupported → stack invalidated → top unknown
  assert.equal(s[s.length - 1].k, 'unknown');
});

// ── Proxy V2 classification ──────────────────────────────────────────────────
test('proxy classification: UNKNOWN / POTENTIAL / CONFIRMED / LIKELY', function () {
  assert.equal(Engine.analyze('6000f3').capabilities.proxy.classification, 'UNKNOWN');
  assert.equal(Engine.analyze('f4').capabilities.proxy.classification, 'POTENTIAL');
  assert.equal(Engine.analyze('f4' + push32(IMPL_SLOT)).capabilities.proxy.classification, 'CONFIRMED');
  assert.equal(Engine.analyze('f4' + push20('a'.repeat(40))).capabilities.proxy.classification, 'LIKELY');
});

test('EIP-1967 admin slot (no impl slot) still confirms proxy', function () {
  assert.equal(Engine.analyze('f4' + push32(ADMIN_SLOT)).capabilities.proxy.classification, 'CONFIRMED');
});

// ── Risk / completeness ──────────────────────────────────────────────────────
test('analysis completeness: COMPLETE / PARTIAL / LIMITED', function () {
  assert.equal(Engine.analyze('5b'.repeat(300)).analysis.completeness, 'COMPLETE');
  assert.equal(Engine.analyze('56').analysis.completeness, 'PARTIAL');
  assert.equal(Engine.analyze('').analysis.completeness, 'LIMITED');
});

test('risk confidence reflects completeness', function () {
  assert.equal(Engine.analyze('5b'.repeat(300)).risk.confidence, 'HIGH');
  assert.equal(Engine.analyze('56').risk.confidence, 'MEDIUM');
  assert.equal(Engine.analyze('').risk.confidence, 'LOW');
});

test('LIMITED analysis is never presented as SAFE', function () {
  var r = Engine.analyze(''); // no bytecode
  assert.equal(r.risk.level, 'LIMITED ANALYSIS');
  assert.notEqual(r.risk.level, 'LOW RISK');
});

test('high-confidence critical finding escalates; low-confidence does not', function () {
  var criticalHigh = Engine.createFinding({ id: 'c', category: 'x', severity: 'CRITICAL', confidence: 'HIGH', title: 't', description: 'd', evidence: [], recommendation: 'r' });
  assert.equal(Engine.assessRisk([criticalHigh], 'COMPLETE').level, 'CRITICAL RISK');

  var criticalLow = Engine.createFinding({ id: 'c2', category: 'x', severity: 'CRITICAL', confidence: 'LOW', title: 't', description: 'd', evidence: [], recommendation: 'r' });
  assert.notEqual(Engine.assessRisk([criticalLow], 'COMPLETE').level, 'CRITICAL RISK');
});

test('findings use reachable instructions only (evidence carries pc/block/reachable)', function () {
  var r = Engine.analyze('ff');
  var f = r.findings.filter(function (x) { return x.id === 'selfdestruct-present'; })[0];
  var ev = f.evidence[0];
  assert.ok(typeof ev.pc === 'number');
  assert.ok(typeof ev.block === 'number');
  assert.equal(ev.reachable, true);
});

console.log('\nAll CFG tests completed.');
