// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — ChatStore (Phase 7.6.1)
//
// ONE centralized persistence module for the chat conversation and application
// context. It is the only place that touches localStorage for chat/session/
// context/transaction persistence (no scattered storage calls in index.html).
//
// Messages get a stable unique id; hydration is idempotent (upsert by id). The
// context whitelist means wallet credentials / private keys are NEVER persisted.
//
// Works in browser and Node (tests) — the storage backend is injectable.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIChatStore = api;
})(function () {
  'use strict';

  var MESSAGES_KEY = 'forgecontract.chat.messages.v1';
  var SESSION_KEY = 'forgecontract.chat.session.v1';
  var CONTEXT_KEY = 'forgecontract.chat.context.v1';
  var TX_KEY = 'forgecontract.chat.txs.v1';
  var SESSIONS_KEY = 'forgecontract.chat.sessions.v2';
  var ACTIVE_SESSION_KEY = 'forgecontract.chat.activeSessionId.v1';

  var _storage = null;

  function getStorage() {
    if (_storage) return _storage;
    try { if (typeof localStorage !== 'undefined') return localStorage; } catch (e) {}
    return null;
  }
  function setStorage(s) { _storage = s || null; }

  function read(key, fallback) {
    var s = getStorage();
    if (!s) return fallback;
    try {
      var v = s.getItem(key);
      if (v === null || v === undefined) return fallback;
      return JSON.parse(v);
    } catch (e) { return fallback; }
  }
  function write(key, value) {
    var s = getStorage();
    if (!s) return false;
    try { s.setItem(key, JSON.stringify(value)); return true; } catch (e) { return false; }
  }
  function remove(key) {
    var s = getStorage();
    if (!s) return false;
    try { s.removeItem(key); return true; } catch (e) { return false; }
  }

  function newId(prefix) {
    return (prefix || 'msg') + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  }

  // Only these context fields may be persisted. Wallet credentials / private
  // keys / seeds / signatures are never in this list.
  var CONTEXT_ALLOWED = [
    'networkId', 'chainId', 'activeContract',
    'lastDeployment', 'lastAuditResult', 'lastAuditAddress', 'lastAuditChain',
    'pendingTransactions'
  ];

  function sanitizeContext(ctx) {
    if (!ctx || typeof ctx !== 'object') return {};
    var out = {};
    CONTEXT_ALLOWED.forEach(function (k) {
      if (k in ctx && ctx[k] !== undefined && ctx[k] !== null) out[k] = ctx[k];
    });
    return out;
  }

  function sanitizeMessage(msg) {
    msg = msg || {};
    return {
      id: (typeof msg.id === 'string' && msg.id) ? msg.id : newId(),
      role: (msg.role === 'user' || msg.role === 'assistant') ? msg.role : (msg.role || 'assistant'),
      content: (typeof msg.content === 'string') ? msg.content : '',
      cardHtml: (typeof msg.cardHtml === 'string') ? msg.cardHtml : null,
      timestamp: (typeof msg.timestamp === 'number') ? msg.timestamp : Date.now(),
      type: (typeof msg.type === 'string') ? msg.type : (msg.role || 'assistant')
    };
  }

  function findIndex(list, id) {
    for (var i = 0; i < list.length; i++) { if (list[i] && list[i].id === id) return i; }
    return -1;
  }

  function saveMessage(msg) {
    var m = sanitizeMessage(msg);
    var list = read(MESSAGES_KEY, []);
    var idx = findIndex(list, m.id);
    if (idx >= 0) list[idx] = m; else list.push(m);
    write(MESSAGES_KEY, list);
    return m;
  }
  function appendMessage(msg) { return saveMessage(msg); }

  function replaceMessage(id, msg) {
    var m = sanitizeMessage(msg);
    m.id = id;
    var list = read(MESSAGES_KEY, []);
    var idx = findIndex(list, id);
    if (idx >= 0) list[idx] = m; else list.push(m);
    write(MESSAGES_KEY, list);
    return m;
  }

  function updateMessage(id, patch) {
    var list = read(MESSAGES_KEY, []);
    var idx = findIndex(list, id);
    if (idx < 0) return null;
    list[idx] = Object.assign({}, list[idx], sanitizeMessage(Object.assign({}, list[idx], patch || {})));
    list[idx].id = id;
    write(MESSAGES_KEY, list);
    return list[idx];
  }

  function loadMessages() { return read(MESSAGES_KEY, []); }
  function clearMessages() { remove(MESSAGES_KEY); }

  function getSession() {
    var s = read(SESSION_KEY, null);
    if (!s || typeof s !== 'object') {
      s = { sessionId: newId('sess'), createdAt: Date.now(), updatedAt: Date.now() };
      write(SESSION_KEY, s);
    }
    return s;
  }
  function setSession(partial) {
    var s = getSession();
    Object.keys(partial || {}).forEach(function (k) { s[k] = partial[k]; });
    s.updatedAt = Date.now();
    write(SESSION_KEY, s);
    return s;
  }

  function saveContext(ctx) {
    var clean = sanitizeContext(ctx);
    var existing = sanitizeContext(read(CONTEXT_KEY, {}));
    var merged = Object.assign({}, existing, clean);
    write(CONTEXT_KEY, merged);
    return merged;
  }
  function loadContext() { return sanitizeContext(read(CONTEXT_KEY, {})); }

  function saveTx(tx) {
    if (!tx || typeof tx.txHash !== 'string' || !tx.txHash) return tx;
    var list = read(TX_KEY, []);
    var idx = -1;
    for (var i = 0; i < list.length; i++) { if (list[i] && list[i].txHash === tx.txHash) { idx = i; break; } }
    var t = Object.assign({}, tx);
    if (idx >= 0) list[idx] = t; else list.push(t);
    write(TX_KEY, list);
    return t;
  }
  function loadTxs() { return read(TX_KEY, []); }
  function updateTx(txHash, patch) {
    var list = read(TX_KEY, []);
    for (var i = 0; i < list.length; i++) {
      if (list[i] && list[i].txHash === txHash) { list[i] = Object.assign({}, list[i], patch || {}); break; }
    }
    write(TX_KEY, list);
  }
  function removeTx(txHash) {
    var list = read(TX_KEY, []).filter(function (t) { return t && t.txHash !== txHash; });
    write(TX_KEY, list);
  }

  // ── Session-scoped messages + context (Phase 7.8, v2, additive) ─────────────
  // Sessions are persisted under SESSIONS_KEY. Each session owns its own
  // messages + context. The global transaction registry (TX_KEY) stays global:
  // a blockchain transaction never depends on a chat's lifetime.
  //
  // The v1 keys (MESSAGES_KEY / SESSION_KEY / CONTEXT_KEY) are left untouched for
  // backward compatibility and are migrated LOSSLESSLY into a legacy session the
  // first time the v2 store is initialized. Nothing here deletes v1 data.

  function sessionsList() {
    migrateLegacyV1();
    return read(SESSIONS_KEY, []) || [];
  }
  function writeSessions(list) { write(SESSIONS_KEY, list); }

  // One-time, lossless, idempotent migration: if v2 has never been written and
  // legacy v1 data exists, preserve it as a `legacy` session. Never removes the
  // v1 keys and never runs twice.
  function migrateLegacyV1() {
    if (read(SESSIONS_KEY, null) !== null) return; // v2 already initialized
    var msgs = read(MESSAGES_KEY, null);
    var ctx = read(CONTEXT_KEY, null);
    var sess = read(SESSION_KEY, null);
    var list = [];
    if (msgs !== null || ctx !== null || sess !== null) {
      list.push({
        sessionId: (sess && sess.sessionId) || newId('legacy'),
        createdAt: (sess && sess.createdAt) || Date.now(),
        updatedAt: (sess && sess.updatedAt) || Date.now(),
        legacy: true,
        messages: (Array.isArray(msgs) ? msgs : []).map(sanitizeMessage),
        context: sanitizeContext(ctx || {})
      });
    }
    writeSessions(list);
  }

  function findSessionIndex(list, id) {
    for (var i = 0; i < list.length; i++) { if (list[i] && list[i].sessionId === id) return i; }
    return -1;
  }

  function createSession() {
    migrateLegacyV1();
    var rec = { sessionId: newId('sess'), createdAt: Date.now(), updatedAt: Date.now(), messages: [], context: {} };
    var list = read(SESSIONS_KEY, []) || [];
    list.push(rec);
    writeSessions(list);
    return rec;
  }

  function listSessions() { return sessionsList(); }

  function getSessionRecord(sessionId) {
    var list = sessionsList();
    var i = findSessionIndex(list, sessionId);
    return i >= 0 ? list[i] : null;
  }

  // Removes ONLY one session's messages + context. Transaction records are
  // untouched (they are global).
  function deleteSession(sessionId) {
    var list = sessionsList().filter(function (s) { return s && s.sessionId !== sessionId; });
    writeSessions(list);
  }

  function loadSessionMessages(sessionId) {
    var s = getSessionRecord(sessionId);
    return s ? (s.messages || []) : [];
  }

  function saveSessionMessage(sessionId, msg) {
    var m = sanitizeMessage(msg);
    var list = sessionsList();
    var i = findSessionIndex(list, sessionId);
    var s;
    if (i >= 0) s = list[i];
    else { s = { sessionId: sessionId, createdAt: Date.now(), updatedAt: Date.now(), messages: [], context: {} }; list.push(s); }
    var mi = findIndex(s.messages || [], m.id);
    if (mi >= 0) s.messages[mi] = m; else s.messages.push(m);
    s.updatedAt = Date.now();
    writeSessions(list);
    return m;
  }

  function clearSessionMessages(sessionId) {
    var list = sessionsList();
    var i = findSessionIndex(list, sessionId);
    if (i < 0) return;
    list[i].messages = [];
    list[i].updatedAt = Date.now();
    writeSessions(list);
  }

  function loadSessionContext(sessionId) {
    var s = getSessionRecord(sessionId);
    return s ? sanitizeContext(s.context || {}) : {};
  }

  function saveSessionContext(sessionId, ctx) {
    var clean = sanitizeContext(ctx);
    var list = sessionsList();
    var i = findSessionIndex(list, sessionId);
    var s;
    if (i >= 0) s = list[i];
    else { s = { sessionId: sessionId, createdAt: Date.now(), updatedAt: Date.now(), messages: [], context: {} }; list.push(s); }
    s.context = Object.assign({}, s.context || {}, clean);
    s.updatedAt = Date.now();
    writeSessions(list);
    return s.context;
  }

  // The id of the chat currently open (persisted so reload + reopen restore it).
  function getActiveSessionId() { return read(ACTIVE_SESSION_KEY, null); }
  function setActiveSessionId(id) { write(ACTIVE_SESSION_KEY, id); }

  return {
    MESSAGES_KEY: MESSAGES_KEY,
    SESSION_KEY: SESSION_KEY,
    CONTEXT_KEY: CONTEXT_KEY,
    TX_KEY: TX_KEY,
    SESSIONS_KEY: SESSIONS_KEY,
    ACTIVE_SESSION_KEY: ACTIVE_SESSION_KEY,
    CONTEXT_ALLOWED: CONTEXT_ALLOWED,
    setStorage: setStorage,
    newId: newId,
    sanitizeContext: sanitizeContext,
    sanitizeMessage: sanitizeMessage,
    saveMessage: saveMessage,
    appendMessage: appendMessage,
    replaceMessage: replaceMessage,
    updateMessage: updateMessage,
    loadMessages: loadMessages,
    clearMessages: clearMessages,
    getSession: getSession,
    setSession: setSession,
    saveContext: saveContext,
    loadContext: loadContext,
    saveTx: saveTx,
    loadTxs: loadTxs,
    updateTx: updateTx,
    removeTx: removeTx,
    migrateLegacyV1: migrateLegacyV1,
    createSession: createSession,
    listSessions: listSessions,
    getSessionRecord: getSessionRecord,
    deleteSession: deleteSession,
    loadSessionMessages: loadSessionMessages,
    saveSessionMessage: saveSessionMessage,
    clearSessionMessages: clearSessionMessages,
    loadSessionContext: loadSessionContext,
    saveSessionContext: saveSessionContext,
    getActiveSessionId: getActiveSessionId,
    setActiveSessionId: setActiveSessionId
  };
});
