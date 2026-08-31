'use strict';
// Phase 5 tests: GenLayer AI Auditor adapter (payload, validation, merge).
// Only the transport (client) is mocked — never a fake vulnerability result.
// Run with:  node tests/genlayer-auditor.test.js
const test = require('node:test');
const assert = require('node:assert');
const Auditor = require('../public/genlayer-auditor.js');
const Engine = require('../public/audit-engine.js');

function fakePayload() {
  return {
    version: '5.0.0',
    contract: { address: '0x' + 'ab'.repeat(20), chainId: '1', bytecodeHash: '0xabcd', bytecodeSize: 10 },
    analysis: {
      completeness: 'PARTIAL',
      evidenceGraph: {
        nodes: [
          { id: 'fn_0', type: 'FUNCTION' },
          { id: 'call_10', type: 'EXTERNAL_CALL' },
          { id: 'slot_0', type: 'STORAGE_SLOT' }
        ],
        edges: [{ from: 'fn_0', to: 'call_10', type: 'CALLS' }]
      }
    },
    findings: [{ id: 'reentrancy-pattern', severity: 'MEDIUM', confidence: 'MEDIUM', category: 'reentrancy' }]
  };
}

function validResponse() {
  return {
    verdict: 'POTENTIAL_VULNERABILITY',
    confidence: 'MEDIUM',
    findings: [
      { id: 'ai_1', category: 'reentrancy', severity: 'MEDIUM', confidence: 'MEDIUM', verdict: 'POTENTIAL_VULNERABILITY', reasoning: 'read-call-write same slot', evidenceRefs: ['call_10', 'slot_0'], contradictions: [], recommendation: 'check CEI' }
    ],
    globalAssessment: { riskLevel: 'MODERATE RISK', confidence: 'MEDIUM', limitations: ['dynamic jumps'] }
  };
}

// ── buildPayload ─────────────────────────────────────────────────────────────
test('buildPayload uses engine payload when present', function () {
  var r = Engine.analyze('600054f16000600155');
  var p = Auditor.buildPayload(r);
  assert.equal(p.version, '5.0.0');
  assert.ok(p.analysis.evidenceGraph);
});

// ── validateResponse ─────────────────────────────────────────────────────────
test('valid response passes validation', function () {
  var v = Auditor.validateResponse(validResponse(), fakePayload());
  assert.equal(v.valid, true, JSON.stringify(v.errors));
});

test('non-object response is invalid', function () {
  var v = Auditor.validateResponse('garbage', fakePayload());
  assert.equal(v.valid, false);
});

test('unknown severity is rejected', function () {
  var r = validResponse(); r.findings[0].severity = 'EXTREME';
  assert.equal(Auditor.validateResponse(r, fakePayload()).valid, false);
});

test('unknown confidence is rejected', function () {
  var r = validResponse(); r.findings[0].confidence = 'SURE';
  assert.equal(Auditor.validateResponse(r, fakePayload()).valid, false);
});

test('missing finding id is rejected', function () {
  var r = validResponse(); delete r.findings[0].id;
  assert.equal(Auditor.validateResponse(r, fakePayload()).valid, false);
});

test('invalid evidence reference is rejected', function () {
  var r = validResponse(); r.findings[0].evidenceRefs = ['ev_999'];
  var v = Auditor.validateResponse(r, fakePayload());
  assert.equal(v.valid, false);
  assert.ok(v.errors.some(function (e) { return e.indexOf('INVALID_AI_EVIDENCE_REFERENCE') !== -1; }));
});

test('unknown verdict is rejected', function () {
  var r = validResponse(); r.verdict = 'TOTALLY_BROKEN';
  assert.equal(Auditor.validateResponse(r, fakePayload()).valid, false);
});

// ── mergeResults ─────────────────────────────────────────────────────────────
test('merge: GenLayer higher severity + HIGH confidence + local support => adopt', function () {
  var local = { risk: { level: 'LOW RISK' }, findings: [{ severity: 'MEDIUM', category: 'reentrancy' }] };
  var gl = { verdict: 'LIKELY_VULNERABILITY', confidence: 'HIGH', globalAssessment: { riskLevel: 'HIGH RISK' }, findings: [{ category: 'reentrancy' }] };
  var m = Auditor.mergeResults(local, gl);
  assert.equal(m.final.risk, 'HIGH RISK');
  assert.equal(m.final.status, 'RESOLVED');
});

test('merge: GenLayer higher severity but LOW confidence => REVIEW_REQUIRED (no auto-upgrade)', function () {
  var local = { risk: { level: 'LOW RISK' }, findings: [] };
  var gl = { verdict: 'LIKELY_VULNERABILITY', confidence: 'LOW', globalAssessment: { riskLevel: 'HIGH RISK' }, findings: [{ category: 'reentrancy' }] };
  var m = Auditor.mergeResults(local, gl);
  assert.equal(m.final.status, 'REVIEW_REQUIRED');
  assert.notEqual(m.final.risk, 'HIGH RISK');
});

test('merge: GenLayer lower/equal severity never erases local evidence', function () {
  var local = { risk: { level: 'HIGH RISK' }, findings: [{ severity: 'HIGH', category: 'selfdestruct' }] };
  var gl = { verdict: 'NO_CONFIRMED_VULNERABILITY', confidence: 'HIGH', globalAssessment: { riskLevel: 'LOW RISK' }, findings: [] };
  var m = Auditor.mergeResults(local, gl);
  assert.equal(m.final.risk, 'HIGH RISK'); // local level preserved
});

// ── analyze (mocked transport) ───────────────────────────────────────────────
test('analyze: success with valid client response => FINALIZED', async function () {
  var local = Engine.analyze('600054f16000600155');
  var ids = Object.keys(local.evidenceIds || {});
  var refId = ids.filter(function (id) { return id.indexOf('call_') === 0; })[0] || ids[0];
  var client = {
    analyzeEvidence: function () {
      return {
        verdict: 'POTENTIAL_VULNERABILITY', confidence: 'MEDIUM',
        findings: [{ id: 'ai_1', category: 'reentrancy', severity: 'MEDIUM', confidence: 'MEDIUM', verdict: 'POTENTIAL_VULNERABILITY', reasoning: 'read-call-write', evidenceRefs: [refId], contradictions: [], recommendation: 'check CEI' }],
        globalAssessment: { riskLevel: 'MODERATE RISK', confidence: 'MEDIUM', limitations: [] }
      };
    }
  };
  var res = await Auditor.analyze(client, local, { timeoutMs: 1000 });
  assert.equal(res.status, 'FINALIZED');
  assert.ok(res.genlayer);
  assert.ok(res.merged);
});

test('analyze: network error => FAILED (local preserved)', async function () {
  var client = { analyzeEvidence: function () { throw new Error('network down'); } };
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(client, local, { timeoutMs: 1000 });
  assert.equal(res.status, 'FAILED');
  assert.equal(res.local, local);
});

test('analyze: timeout => TIMEOUT (local preserved)', async function () {
  var client = { analyzeEvidence: function () { return new Promise(function () {}); } };
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(client, local, { timeoutMs: 20 });
  assert.equal(res.status, 'TIMEOUT');
});

test('analyze: invalid response => INVALID (local preserved)', async function () {
  var client = { analyzeEvidence: function () { return { verdict: 'NOPE' }; } };
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(client, local, { timeoutMs: 1000 });
  assert.equal(res.status, 'INVALID');
});

test('analyze: no client => FAILED GENLAYER_UNAVAILABLE (no fake result)', async function () {
  var local = Engine.analyze('f1');
  var res = await Auditor.analyze(null, local, { timeoutMs: 1000 });
  assert.equal(res.status, 'FAILED');
  assert.equal(res.error, 'GENLAYER_UNAVAILABLE');
  assert.equal(res.genlayer, null);
});

console.log('\nAll genlayer-auditor tests completed.');
