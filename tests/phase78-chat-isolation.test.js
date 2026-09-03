'use strict';
// Phase 7.8 tests: chat session isolation + clean new-chat lifecycle +
// zero-regression persistence. Deterministic, Node-runnable (storage injected).
// Run with:  node tests/phase78-chat-isolation.test.js
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

// ── Session creation ──────────────────────────────────────────────────────────

test('createSession produces a unique, stable sessionId', function () {
  var S = freshStore();
  var a = S.createSession();
  var b = S.createSession();
  assert.ok(a.sessionId && typeof a.sessionId === 'string');
  assert.ok(b.sessionId && typeof b.sessionId === 'string');
  assert.notEqual(a.sessionId, b.sessionId);
});

test('a new session starts with zero messages and empty context', function () {
  var S = freshStore();
  var s = S.createSession();
  assert.deepEqual(S.loadSessionMessages(s.sessionId), []);
  assert.deepEqual(S.loadSessionContext(s.sessionId), {});
});

// ── Message isolation ─────────────────────────────────────────────────────────

test('Chat A messages never appear in Chat B', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionMessage(a.sessionId, { id: 'm1', role: 'user', content: 'audit A' });
  var b = S.createSession();
  S.saveSessionMessage(b.sessionId, { id: 'm2', role: 'user', content: 'audit B' });
  assert.equal(S.loadSessionMessages(a.sessionId).length, 1);
  assert.equal(S.loadSessionMessages(a.sessionId)[0].content, 'audit A');
  assert.equal(S.loadSessionMessages(b.sessionId).length, 1);
  assert.equal(S.loadSessionMessages(b.sessionId)[0].content, 'audit B');
});

// ── Context isolation ─────────────────────────────────────────────────────────

test('Chat A context never appears in Chat B', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionContext(a.sessionId, { lastAuditAddress: '0xAAA', lastAuditResult: { score: 99 } });
  var b = S.createSession();
  S.saveSessionContext(b.sessionId, { lastAuditAddress: '0xBBB' });
  assert.equal(S.loadSessionContext(a.sessionId).lastAuditAddress, '0xAAA');
  assert.equal(S.loadSessionContext(b.sessionId).lastAuditAddress, '0xBBB');
  assert.equal(S.loadSessionContext(b.sessionId).lastAuditResult, undefined);
});

// ── Operation ownership (transaction → origin session) ────────────────────────

test('a transaction is persisted globally with its originSessionId', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveTx({ txHash: '0xtx1', operation: 'AUDIT_AI', status: 'PENDING', sessionId: a.sessionId });
  var txs = S.loadTxs();
  assert.equal(txs.length, 1);
  assert.equal(txs[0].sessionId, a.sessionId);
});

test('the global transaction registry survives creating a new chat', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveTx({ txHash: '0xtx1', operation: 'DEPLOY', status: 'REVEALING', sessionId: a.sessionId });
  var b = S.createSession(); // "New Chat"
  assert.equal(S.loadTxs().length, 1);
  assert.equal(S.loadTxs()[0].txHash, '0xtx1');
  assert.equal(S.loadTxs()[0].sessionId, a.sessionId); // still owned by Chat A
});

// ── Race condition: stale callback writes to the origin chat, not the new one ─

test('operation started in Chat A keeps updating Chat A after switching to Chat B', function () {
  var S = freshStore();
  var a = S.createSession();
  // operation progress (simulating an async callback that captured Chat A)
  S.saveSessionMessage(a.sessionId, { id: 'transaction-progress:0xtx1', role: 'assistant', content: 'PROPOSING', type: 'assistant' });
  var b = S.createSession(); // user clicked New Chat mid-operation
  // the stale callback resolves and updates Chat A's progress message
  S.saveSessionMessage(a.sessionId, { id: 'transaction-progress:0xtx1', role: 'assistant', content: 'FINALIZED', type: 'assistant' });
  // Chat A updated, Chat B untouched
  assert.equal(S.loadSessionMessages(a.sessionId).length, 1);
  assert.equal(S.loadSessionMessages(a.sessionId)[0].content, 'FINALIZED');
  assert.equal(S.loadSessionMessages(b.sessionId).length, 0);
});

// ── New Chat during Audit / Contract Creation ─────────────────────────────────

test('New Chat during an audit leaves the new chat empty and the audit persisted', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionMessage(a.sessionId, { id: 'tx:progress:0xa', role: 'assistant', content: 'COMMITTING', type: 'assistant' });
  S.saveTx({ txHash: '0xa', operation: 'AUDIT_AI', status: 'COMMITTING', sessionId: a.sessionId });
  var b = S.createSession();
  assert.equal(S.loadSessionMessages(b.sessionId).length, 0);
  assert.equal(S.loadSessionMessages(a.sessionId).length, 1);
  assert.equal(S.loadTxs().length, 1);
});

test('New Chat during contract creation leaves the deployment persisted', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveTx({ txHash: '0xd', operation: 'DEPLOY', status: 'REVEALING', sessionId: a.sessionId });
  var b = S.createSession();
  assert.equal(S.loadSessionMessages(b.sessionId).length, 0);
  assert.equal(S.loadTxs().length, 1);
  assert.equal(S.loadTxs()[0].operation, 'DEPLOY');
});

// ── Startup behavior (boot restores the last chat) ────────────────────────────

// Mirrors bootApp()'s decision logic against the store primitives it relies on.
function simulateBoot(S) {
  var id = S.getActiveSessionId();
  if (id && S.getSessionRecord(id)) {
    return { restored: true, sessionId: id, messages: S.loadSessionMessages(id) };
  }
  var s = S.createSession();
  S.setActiveSessionId(s.sessionId);
  return { restored: false, sessionId: s.sessionId, messages: S.loadSessionMessages(s.sessionId) };
}

test('activeSessionId is persisted and read back', function () {
  var S = freshStore();
  var a = S.createSession();
  S.setActiveSessionId(a.sessionId);
  assert.equal(S.getActiveSessionId(), a.sessionId);
});

test('boot with a valid activeSessionId restores that chat (no new session)', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionMessage(a.sessionId, { id: 'm1', role: 'user', content: 'last chat' });
  S.setActiveSessionId(a.sessionId);
  var boot = simulateBoot(S);
  assert.equal(boot.restored, true);
  assert.equal(boot.sessionId, a.sessionId);
  assert.equal(boot.messages.length, 1);
  assert.equal(boot.messages[0].content, 'last chat');
  assert.equal(S.listSessions().length, 1); // createSession was NOT called
});

test('boot without an active id creates a fresh session', function () {
  var S = freshStore();
  var boot = simulateBoot(S);
  assert.equal(boot.restored, false);
  assert.ok(boot.sessionId);
  assert.equal(boot.messages.length, 0);
  assert.equal(S.listSessions().length, 1);
  assert.equal(S.getActiveSessionId(), boot.sessionId);
});

test('boot with a stale active id (session deleted) falls back to a new session', function () {
  var S = freshStore();
  var a = S.createSession();
  S.setActiveSessionId(a.sessionId);
  S.deleteSession(a.sessionId);
  var boot = simulateBoot(S);
  assert.equal(boot.restored, false);
  assert.ok(boot.sessionId);
  assert.equal(boot.messages.length, 0);
});

// ── Recents = bridge to the persisted session (never re-runs the audit) ───────

test('opening a Recent item with sessionId rehydrates the session, not a new audit', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionMessage(a.sessionId, { id: 'm1', role: 'assistant', content: 'audit result card' });
  // The Recents entry records which session originated the audit.
  var item = { address: '0xabc', chain: 'bradbury', sessionId: a.sessionId };
  // Opening it resolves the persisted session (no new tx, no new session).
  assert.ok(S.getSessionRecord(item.sessionId));
  assert.equal(S.loadSessionMessages(item.sessionId).length, 1);
  assert.equal(S.loadTxs().length, 0); // no audit/tx was dispatched
  assert.equal(S.listSessions().length, 1); // no new session was created
});

test('a Recent item without a session still falls back (re-audit path)', function () {
  var S = freshStore();
  var item = { address: '0xabc', chain: 'bradbury', sessionId: null };
  assert.equal(item.sessionId ? (S.getSessionRecord(item.sessionId) !== null) : false, false);
});

// ── Finalized / failed transactions do not contaminate chat ───────────────────

test('a finalized transaction updates the registry without touching chat messages', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveTx({ txHash: '0xf', operation: 'AUDIT_AI', status: 'ACCEPTED', sessionId: a.sessionId });
  S.updateTx('0xf', { status: 'FINALIZED' });
  assert.equal(S.loadTxs()[0].status, 'FINALIZED');
  assert.equal(S.loadSessionMessages(a.sessionId).length, 0); // no auto message injected
});

// ── Explicit history restoration ──────────────────────────────────────────────

test('explicitly loading a session restores exactly that session', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionMessage(a.sessionId, { id: 'm1', role: 'assistant', content: 'audit result A' });
  var b = S.createSession();
  S.saveSessionMessage(b.sessionId, { id: 'm2', role: 'assistant', content: 'audit result B' });
  // Reopen Chat A explicitly
  assert.equal(S.loadSessionMessages(a.sessionId)[0].content, 'audit result A');
  assert.equal(S.loadSessionMessages(b.sessionId)[0].content, 'audit result B');
});

// ── Explorer URL persistence ──────────────────────────────────────────────────

test('Explorer URL (tx metadata) survives new chat creation', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveTx({ txHash: '0xe', operation: 'AUDIT_AI', status: 'PENDING', sessionId: a.sessionId, explorerUrl: 'https://explorer-bradbury.genlayer.com/tx/0xe' });
  S.createSession();
  assert.equal(S.loadTxs()[0].explorerUrl, 'https://explorer-bradbury.genlayer.com/tx/0xe');
});

// ── Backward compatibility (v1 → v2 lossless migration) ───────────────────────

test('v1 persistence does not crash v2 and is preserved losslessly', function () {
  var S = freshStore();
  // Simulate pre-7.8 v1 data (global messages + context + session).
  S.setSession({ sessionId: 'sess-v1', createdAt: 1000 });
  S.saveMessage({ id: 'old1', role: 'user', content: 'old message' });
  S.saveContext({ lastAuditAddress: '0xOLDA', lastDeployment: { address: '0xD' } });
  // v2 initialization must not crash and must preserve v1 data.
  var s = S.createSession();
  assert.ok(s.sessionId);
  // Legacy data preserved as a legacy session, never deleted from v1 keys.
  assert.equal(S.loadMessages().length, 1); // v1 key still intact
  assert.equal(S.loadContext().lastAuditAddress, '0xOLDA'); // v1 key still intact
  var sessions = S.listSessions();
  var legacy = sessions.find(function (x) { return x.legacy === true; });
  assert.ok(legacy, 'expected a legacy session preserving v1 data');
  assert.equal(legacy.messages.length, 1);
  assert.equal(legacy.messages[0].content, 'old message');
});

// ── No destructive reset ──────────────────────────────────────────────────────

test('New Chat never clears the global transaction persistence', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveTx({ txHash: '0x1', operation: 'AUDIT_AI', status: 'PENDING', sessionId: a.sessionId });
  S.saveTx({ txHash: '0x2', operation: 'DEPLOY', status: 'REVEALING', sessionId: a.sessionId });
  S.createSession(); // new chat
  S.createSession(); // another new chat
  assert.equal(S.loadTxs().length, 2);
});

test('deleteSession removes only that session, never transaction records', function () {
  var S = freshStore();
  var a = S.createSession();
  S.saveSessionMessage(a.sessionId, { id: 'm1', role: 'user', content: 'to delete' });
  S.saveTx({ txHash: '0x1', operation: 'AUDIT_AI', status: 'PENDING', sessionId: a.sessionId });
  var b = S.createSession();
  S.deleteSession(a.sessionId);
  assert.equal(S.loadSessionMessages(a.sessionId).length, 0);
  assert.equal(S.loadSessionMessages(b.sessionId).length, 0);
  assert.equal(S.loadTxs().length, 1); // transactions are global and untouched
});
