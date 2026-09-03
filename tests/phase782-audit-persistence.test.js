'use strict';
// Phase 7.8.2 tests: Contract Studio → GenLayer audit result persistence.
// Verifies the audit result flows through the SAME ChatStore session-context
// persistence used by normal audits (lastAuditResult/lastAuditAddress/
// lastAuditChain), preserves GENLAYER_SOURCE_REVIEW semantics, survives reload
// (rehydration from the store, not from an in-memory cache), and stays owned by
// the originating session. Run with:  node tests/phase782-audit-persistence.test.js
const test = require('node:test');
const assert = require('node:assert');
const ChatStore = require('../public/chat-store.js');

function memStorage() {
  var m = {};
  return {
    getItem: function (k) { return Object.prototype.hasOwnProperty.call(m, k) ? m[k] : null; },
    setItem: function (k, v) { m[k] = String(v); },
    removeItem: function (k) { delete m[k]; },
    dump: function () { return m; }
  };
}

function freshStore() {
  ChatStore.setStorage(memStorage());
  return ChatStore;
}

// The shape produced by reviewGenLayerContract() for a GenLayer Intelligent
// Contract (UNKNOWN ⇒ null score, never a fabricated number).
function genLayerSourceReview(opts) {
  opts = opts || {};
  return {
    auditType: 'GENLAYER_SOURCE_REVIEW',
    networkId: opts.networkId || 'genlayerBradbury',
    networkName: opts.networkName || 'GenLayer Bradbury Testnet',
    chainId: opts.chainId || 4221,
    address: opts.address || '0x119Ac58AF8546Df0B0E55eB24277C756d9458000',
    txHash: opts.txHash || null,
    risk: 'UNKNOWN',
    confidence: 'LOW',
    score: null,
    verdict: 'UNKNOWN',
    findings: opts.findings || [],
    analysis: { sourceAvailable: false, schemaAvailable: true, source: null, review: null, contractType: 'GENLAYER' },
    summary: 'GenLayer intelligent contract — source/schema-based security review.'
  };
}

// Mirrors addToHistory()'s dedup/insert semantics (address+chain identity) so we
// can assert that re-persisting the same audit does not create duplicate entries.
function historyUpsert(list, entry) {
  var lower = String(entry.address).toLowerCase();
  var out = list.filter(function (x) { return !(x.address === lower && x.chain === entry.chain); });
  out.unshift({ address: lower, chain: entry.chain, score: entry.score, verdict: entry.verdict, auditType: entry.auditType, ts: entry.ts, sessionId: entry.sessionId || undefined });
  if (out.length > 30) out = out.slice(0, 30);
  return out;
}

// ── Persistence of the source-review result into session context ──────────────

test('Contract Studio audit result persists into the session context', function () {
  var S = freshStore();
  var s = S.createSession();
  var result = genLayerSourceReview({ findings: [{ id: 'f1', severity: 'INFO', confidence: 'LOW', title: 'source note' }] });
  S.saveSessionContext(s.sessionId, { lastAuditResult: result, lastAuditAddress: result.address, lastAuditChain: result.chainId });
  var ctx = S.loadSessionContext(s.sessionId);
  assert.ok(ctx.lastAuditResult);
  assert.equal(ctx.lastAuditResult.auditType, 'GENLAYER_SOURCE_REVIEW');
  assert.equal(ctx.lastAuditAddress, result.address);
  assert.equal(ctx.lastAuditChain, result.chainId);
});

test('GENLAYER_SOURCE_REVIEW semantics are preserved: score null, UNKNOWN, LOW', function () {
  var S = freshStore();
  var s = S.createSession();
  var result = genLayerSourceReview();
  S.saveSessionContext(s.sessionId, { lastAuditResult: result });
  var restored = S.loadSessionContext(s.sessionId).lastAuditResult;
  assert.equal(restored.score, null);                 // never a fabricated number
  assert.equal(restored.verdict, 'UNKNOWN');          // UNKNOWN stays UNKNOWN
  assert.equal(restored.confidence, 'LOW');
  assert.equal(restored.auditType, 'GENLAYER_SOURCE_REVIEW');
});

test('findings, contract address, chainId and network are preserved', function () {
  var S = freshStore();
  var s = S.createSession();
  var findings = [{ id: 'f1', severity: 'INFO', confidence: 'LOW', category: 'other', title: 'note A' }];
  var result = genLayerSourceReview({ findings: findings, chainId: 4221, networkId: 'genlayerBradbury' });
  S.saveSessionContext(s.sessionId, { lastAuditResult: result, lastAuditAddress: result.address, lastAuditChain: result.chainId });
  var ctx = S.loadSessionContext(s.sessionId);
  assert.equal(ctx.lastAuditResult.findings.length, 1);
  assert.equal(ctx.lastAuditResult.findings[0].title, 'note A');
  assert.equal(ctx.lastAuditResult.address, result.address);
  assert.equal(ctx.lastAuditResult.chainId, 4221);
  assert.equal(ctx.lastAuditResult.networkId, 'genlayerBradbury');
});

// ── Reload / rehydration (no in-memory cache required) ────────────────────────

test('reload restores the audit from the store (not from GL_AUDIT_STORE cache)', function () {
  // A single backing store (like localStorage) survives a reload; only the
  // module's in-memory reference is dropped.
  var mem = memStorage();
  ChatStore.setStorage(mem);
  var s = ChatStore.createSession();
  var result = genLayerSourceReview();
  ChatStore.saveSessionContext(s.sessionId, { lastAuditResult: result, lastAuditAddress: result.address, lastAuditChain: result.chainId });
  // Simulate reload: detach + reattach to the same persisted backend.
  ChatStore.setStorage(null);
  ChatStore.setStorage(mem);
  var ctx = ChatStore.loadSessionContext(s.sessionId);
  assert.ok(ctx.lastAuditResult);
  assert.equal(ctx.lastAuditResult.auditType, 'GENLAYER_SOURCE_REVIEW');
  assert.equal(ctx.lastAuditAddress, result.address);
});

// ── Session ownership / no leak ───────────────────────────────────────────────

test('the audit belongs to the originating session and never leaks into another chat', function () {
  var S = freshStore();
  var a = S.createSession();
  var result = genLayerSourceReview();
  S.saveSessionContext(a.sessionId, { lastAuditResult: result, lastAuditAddress: result.address, lastAuditChain: result.chainId });
  var b = S.createSession(); // user creates a new chat
  assert.equal(S.loadSessionContext(b.sessionId).lastAuditResult, undefined);
  assert.equal(S.loadSessionContext(a.sessionId).lastAuditResult.auditType, 'GENLAYER_SOURCE_REVIEW');
});

test('creating a new chat does not drop the persisted audit of the previous chat', function () {
  var S = freshStore();
  var a = S.createSession();
  var result = genLayerSourceReview();
  S.saveSessionContext(a.sessionId, { lastAuditResult: result, lastAuditAddress: result.address });
  S.createSession(); // New Chat
  assert.equal(S.loadSessionContext(a.sessionId).lastAuditAddress, result.address);
});

// ── History entry semantics + dedup (mirrors addToHistory) ────────────────────

test('a Contract Studio audit history entry identifies GENLAYER_SOURCE_REVIEW', function () {
  var result = genLayerSourceReview();
  var entry = { address: result.address, chain: 'GenLayer Bradbury Testnet', score: result.score, verdict: result.verdict, auditType: result.auditType, ts: Date.now(), sessionId: 'sess-a' };
  var list = historyUpsert([], entry);
  assert.equal(list.length, 1);
  assert.equal(list[0].auditType, 'GENLAYER_SOURCE_REVIEW');
  assert.equal(list[0].score, null);
  assert.equal(list[0].verdict, 'UNKNOWN');
});

test('re-persisting the same audit does not create duplicate history entries', function () {
  var result = genLayerSourceReview();
  var mk = function () { return { address: result.address, chain: 'GenLayer Bradbury Testnet', score: null, verdict: 'UNKNOWN', auditType: 'GENLAYER_SOURCE_REVIEW', ts: Date.now(), sessionId: 'sess-a' }; };
  var list = historyUpsert([], mk());
  list = historyUpsert(list, mk());
  list = historyUpsert(list, mk());
  assert.equal(list.length, 1);
});

test('distinct contracts produce distinct history entries', function () {
  var a = genLayerSourceReview({ address: '0xAAA0000000000000000000000000000000000000' });
  var b = genLayerSourceReview({ address: '0xBBB0000000000000000000000000000000000000' });
  var list = historyUpsert([], { address: a.address, chain: 'GenLayer Bradbury Testnet', score: null, verdict: 'UNKNOWN', auditType: 'GENLAYER_SOURCE_REVIEW', ts: Date.now(), sessionId: 'sess-a' });
  list = historyUpsert(list, { address: b.address, chain: 'GenLayer Bradbury Testnet', score: null, verdict: 'UNKNOWN', auditType: 'GENLAYER_SOURCE_REVIEW', ts: Date.now(), sessionId: 'sess-a' });
  assert.equal(list.length, 2);
});
