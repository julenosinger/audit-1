'use strict';
// Tests for the Local Audit Engine (public/audit-engine.js).
// Run with:  node tests/audit-engine.test.js
const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../public/audit-engine.js');

const IMPL_SLOT = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';

function push1(byte) { return '60' + byte; }
function push4(sel) { return '63' + sel; }
function push32(hex) { return '7f' + hex; }

function findById(result, id) {
  return result.findings.filter(function (f) { return f.id === id; })[0];
}

function hasFinding(result, id) {
  return result.findings.some(function (f) { return f.id === id; });
}

// ── Disassembler / PUSH data ─────────────────────────────────────────────────
test('PUSH1 containing 0xff does NOT report SELFDESTRUCT', function () {
  var dis = Engine.disassemble(push1('ff'));
  assert.equal(dis.valid, true);
  assert.equal(dis.instructions.length, 1);
  assert.equal(dis.instructions[0].opcode, 'PUSH1');
  assert.equal(dis.instructions[0].argument, 'ff');

  var r = Engine.analyze(push1('ff'));
  assert.ok(!hasFinding(r, 'selfdestruct-present'), 'must not flag selfdestruct from PUSH data');
});

test('PUSH32 containing 0xf4 does NOT report DELEGATECALL', function () {
  var code = push32('f4' + '00'.repeat(31));
  var dis = Engine.disassemble(code);
  assert.equal(dis.instructions.length, 1);
  assert.equal(dis.instructions[0].opcode, 'PUSH32');

  var r = Engine.analyze(code);
  assert.ok(!hasFinding(r, 'external-call-present'), 'must not flag delegatecall from PUSH data');
  assert.equal(r.capabilities.proxy.detected, false);
});

test('real SELFDESTRUCT is reported', function () {
  var r = Engine.analyze('ff');
  assert.ok(hasFinding(r, 'selfdestruct-present'));
  assert.equal(findById(r, 'selfdestruct-present').severity, 'MEDIUM');
});

test('real DELEGATECALL is reported as potential proxy (LOW confidence)', function () {
  var r = Engine.analyze('f4');
  assert.equal(r.capabilities.proxy.detected, true);
  assert.equal(r.capabilities.proxy.confidence, 'LOW');
  assert.ok(hasFinding(r, 'proxy-potential'));
});

test('real CALL is reported as an external call (not reentrancy)', function () {
  var r = Engine.analyze('f1');
  assert.ok(hasFinding(r, 'external-call-present'));
  assert.ok(!hasFinding(r, 'reentrancy-potential'), 'CALL alone must not be reentrancy');
});

test('invalid bytecode produces invalid finding', function () {
  var r = Engine.analyze('zz');
  assert.ok(hasFinding(r, 'bytecode-invalid'));
  assert.equal(r.risk.level, 'LIMITED ANALYSIS');
});

test('empty bytecode is treated as EOA / limited analysis', function () {
  var r = Engine.analyze('');
  assert.equal(r.contract.type, 'EOA');
  assert.equal(r.risk.level, 'LIMITED ANALYSIS');
});

// ── Proxy ────────────────────────────────────────────────────────────────────
test('normal contract (no DELEGATECALL) is not a proxy', function () {
  var r = Engine.analyze('6000f3'); // PUSH1 0 RETURN
  assert.equal(r.capabilities.proxy.detected, false);
});

test('DELEGATECALL + EIP-1967 implementation slot => proxy HIGH confidence', function () {
  var code = 'f4' + push32(IMPL_SLOT);
  var r = Engine.analyze(code);
  assert.equal(r.capabilities.proxy.detected, true);
  assert.equal(r.capabilities.proxy.confidence, 'HIGH');
  assert.ok(hasFinding(r, 'proxy-detected'));
});

test('DELEGATECALL without slot => potential proxy, LOW confidence (never asserted as proxy)', function () {
  var r = Engine.analyze('f4');
  assert.equal(r.capabilities.proxy.detected, true);
  assert.equal(r.capabilities.proxy.confidence, 'LOW');
  assert.ok(!hasFinding(r, 'proxy-detected'));
});

// ── Token / mint / burn / pause / blacklist ─────────────────────────────────
test('ERC-20 selectors => token type detected', function () {
  var code = push4('a9059cbb') + push4('095ea7b3') + push4('70a08231') + push4('18160ddd');
  var r = Engine.analyze(code);
  assert.equal(r.contract.type, 'ERC-20');
});

test('mint selector => mint present, restriction unknown, severity MEDIUM (not CRITICAL)', function () {
  var r = Engine.analyze(push4('40c10f19'));
  assert.equal(r.capabilities.mint.present, true);
  assert.equal(r.capabilities.mint.restriction, 'unknown');
  var f = findById(r, 'mint-present');
  assert.ok(f, 'mint finding present');
  assert.equal(f.severity, 'MEDIUM');
});

test('burn selector => burn present (INFO)', function () {
  var r = Engine.analyze(push4('42966c68'));
  assert.equal(r.capabilities.burn.present, true);
  assert.ok(hasFinding(r, 'burn-present'));
});

test('pause + unpause selectors => pause mechanism detected', function () {
  var r = Engine.analyze(push4('8456cb59') + push4('3f4ba83a'));
  assert.equal(r.capabilities.pause, 'Detected');
  assert.ok(hasFinding(r, 'pause-mechanism'));
});

test('blacklist via ABI => detected; without ABI => unknown', function () {
  var withAbi = Engine.analyze('5b', { abi: [{ type: 'function', name: 'setBlacklist', inputs: [] }] });
  assert.equal(withAbi.capabilities.blacklist, 'Detected');

  var noAbi = Engine.analyze('5b');
  assert.equal(noAbi.capabilities.blacklist, 'Unknown');
});

test('tx.origin (ORIGIN) => MEDIUM severity, MEDIUM confidence', function () {
  var r = Engine.analyze('32'); // ORIGIN
  var f = findById(r, 'tx-origin-usage');
  assert.ok(f);
  assert.equal(f.severity, 'MEDIUM');
  assert.equal(f.confidence, 'MEDIUM');
});

// ── Risk engine ──────────────────────────────────────────────────────────────
test('benign bytecode with no findings => LOW RISK, score 100', function () {
  var r = Engine.analyze('5b'.repeat(300));
  assert.equal(r.findings.length, 0);
  assert.equal(r.risk.score, 100);
  assert.equal(r.risk.level, 'LOW RISK');
});

test('risk: no finding => LOW RISK (never "SAFE")', function () {
  var risk = Engine.assessRisk([], 'full');
  assert.equal(risk.level, 'LOW RISK');
  assert.notEqual(risk.level, 'SAFE');
});

test('risk: CRITICAL finding (HIGH confidence) escalates to CRITICAL RISK', function () {
  var f = Engine.createFinding({ id: 'c', category: 'x', severity: 'CRITICAL', confidence: 'HIGH', title: 't', description: 'd', evidence: [], recommendation: 'r' });
  var risk = Engine.assessRisk([f], 'full');
  assert.equal(risk.level, 'CRITICAL RISK');
  assert.ok(risk.score < 50);
});

test('risk: CRITICAL finding with LOW confidence does NOT escalate', function () {
  var f = Engine.createFinding({ id: 'c', category: 'x', severity: 'CRITICAL', confidence: 'LOW', title: 't', description: 'd', evidence: [], recommendation: 'r' });
  var risk = Engine.assessRisk([f], 'full');
  assert.notEqual(risk.level, 'CRITICAL RISK');
});

test('risk: HIGH severity + HIGH confidence escalates to HIGH RISK', function () {
  var f = Engine.createFinding({ id: 'h', category: 'x', severity: 'HIGH', confidence: 'HIGH', title: 't', description: 'd', evidence: [], recommendation: 'r' });
  var risk = Engine.assessRisk([f], 'full');
  assert.equal(risk.level, 'HIGH RISK');
});

test('findings carry severity, confidence, evidence, recommendation', function () {
  var r = Engine.analyze('ff');
  var f = findById(r, 'selfdestruct-present');
  assert.ok(f.severity);
  assert.ok(f.confidence);
  assert.ok(Array.isArray(f.evidence) && f.evidence.length > 0);
  assert.ok(f.recommendation.length > 0);
  assert.ok(typeof f.scoreImpact === 'number');
});

// ── Safety: contract-derived data must not contain HTML/script ──────────────
test('engine output contains no raw HTML/script injection vectors', function () {
  var inputs = ['ff', 'f4', 'f1', push1('ff'), push32('f4' + '00'.repeat(31)), '6000f3'];
  inputs.forEach(function (code) {
    var r = Engine.analyze(code);
    [r.summary, r.context, r.analysisText].forEach(function (s) {
      if (typeof s === 'string') {
        assert.ok(!/</.test(s) && !/>/.test(s), 'no angle brackets in output');
      }
    });
    r.findings.forEach(function (f) {
      ['title', 'description', 'recommendation'].forEach(function (k) {
        assert.ok(!/</.test(f[k]) && !/>/.test(f[k]), 'no HTML in ' + k);
      });
      (f.evidence || []).forEach(function (e) {
        assert.ok(!/</.test(e.text) && !/>/.test(e.text), 'no HTML in evidence');
      });
    });
  });
});

test('disassemble handles odd-length and 0x-prefixed bytecode', function () {
  assert.equal(Engine.disassemble('0x6000f3').valid, true);
  assert.equal(Engine.normalizeHex('0x0F').length, 2); // odd padded
});

console.log('\nAll audit-engine tests completed.');
