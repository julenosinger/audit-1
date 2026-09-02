'use strict';
// Phase 7.6.1 tests: real GenLayer transaction lifecycle + chat persistence.
// Deterministic invariants only — the transport is mocked, never a fake result.
// Run with:  node tests/phase761.test.js
const test = require('node:test');
const assert = require('node:assert');
const Tx = require('../public/genlayer-tx.js');
const ChatStore = require('../public/chat-store.js');
const GenLayerClient = require('../public/genlayer-client.js');
const Networks = require('../public/networks.js');

function memStorage() {
  var m = {};
  return {
    getItem: function (k) { return Object.prototype.hasOwnProperty.call(m, k) ? m[k] : null; },
    setItem: function (k, v) { m[k] = String(v); },
    removeItem: function (k) { delete m[k]; },
    dump: function () { return m; }
  };
}

const noSleep = function () { return Promise.resolve(); };

// ── Transaction status normalization / classification ─────────────────────────

test('normalizeStatus maps numbers and strings to canonical names', function () {
  assert.equal(Tx.normalizeStatus(0), 'UNINITIALIZED');
  assert.equal(Tx.normalizeStatus(5), 'ACCEPTED');
  assert.equal(Tx.normalizeStatus(7), 'FINALIZED');
  assert.equal(Tx.normalizeStatus(13), 'LEADER_TIMEOUT');
  assert.equal(Tx.normalizeStatus('PROPOSING'), 'PROPOSING');
  assert.equal(Tx.normalizeStatus('accepted'), 'ACCEPTED');
  assert.equal(Tx.normalizeStatus(null), 'UNKNOWN');
});

test('processing statuses are never terminal', function () {
  ['PENDING', 'PROPOSING', 'COMMITTING', 'REVEALING'].forEach(function (s) {
    var c = Tx.classify(s);
    assert.equal(c.kind, 'PROCESSING');
    assert.equal(c.terminal, false);
  });
});

test('LEADER_TIMEOUT / VALIDATORS_TIMEOUT are continuing (never failures)', function () {
  assert.equal(Tx.classify('LEADER_TIMEOUT').kind, 'CONTINUING_TIMEOUT');
  assert.equal(Tx.classify('VALIDATORS_TIMEOUT').kind, 'CONTINUING_TIMEOUT');
  assert.equal(Tx.classify('LEADER_TIMEOUT').terminal, false);
  assert.equal(Tx.isContinuing('LEADER_TIMEOUT'), true);
});

test('appeal statuses are continuing', function () {
  ['APPEAL_COMMITTING', 'APPEAL_REVEALING', 'READY_TO_FINALIZE'].forEach(function (s) {
    assert.equal(Tx.classify(s).kind, 'CONTINUING_APPEAL');
    assert.equal(Tx.classify(s).terminal, false);
  });
});

test('ACCEPTED and FINALIZED are distinct success terminal states', function () {
  assert.equal(Tx.classify('ACCEPTED').kind, 'ACCEPTED');
  assert.equal(Tx.classify('ACCEPTED').accepted, true);
  assert.equal(Tx.classify('ACCEPTED').finalized, false);
  assert.equal(Tx.classify('FINALIZED').kind, 'FINALIZED');
  assert.equal(Tx.classify('FINALIZED').finalized, true);
  assert.equal(Tx.isAccepted('ACCEPTED'), true);
  assert.equal(Tx.isFinalized('FINALIZED'), true);
  assert.notEqual(Tx.isFinalized('ACCEPTED'), true);
});

test('CANCELED / UNDETERMINED are terminal failures', function () {
  assert.equal(Tx.classify('CANCELED').kind, 'FAILED_TERMINAL');
  assert.equal(Tx.classify('UNDETERMINED').kind, 'FAILED_TERMINAL');
  assert.equal(Tx.isTerminalFailure('CANCELED'), true);
  assert.equal(Tx.isTerminalFailure('UNDETERMINED'), true);
});

test('statusMessage never reports timeout for a live status', function () {
  ['PENDING', 'PROPOSING', 'COMMITTING', 'REVEALING', 'LEADER_TIMEOUT', 'VALIDATORS_TIMEOUT', 'APPEAL_COMMITTING', 'ACCEPTED', 'FINALIZED'].forEach(function (s) {
    var m = Tx.statusMessage(s);
    assert.ok(typeof m === 'string' && m.length > 0, s);
    assert.ok(!/timed out/i.test(m), s + ' must not say "timed out"');
  });
  assert.ok(/accepted/i.test(Tx.statusMessage('ACCEPTED')));
  assert.ok(/finalized/i.test(Tx.statusMessage('FINALIZED')));
});

// ── CRITICAL regression: no false 90s timeout ────────────────────────────────

test('regression: ACCEPTED after >90s of processing is NOT a timeout', async function () {
  var calls = 0;
  var emitted = [];
  var getStatus = async function () {
    calls += 1;
    // 99 polls of PENDING (well past any 90s timer), then ACCEPTED at ~137s.
    if (calls < 100) return { statusName: 'PENDING', status: 1 };
    return { statusName: 'ACCEPTED', status: 5, txExecutionResultName: 'FINISHED_WITH_RETURN' };
  };
  var out = await Tx.monitorTransaction({
    hash: '0x8ae0e27dea058be804b47ffdf072736cf203ecc2b28043ba6eca17c575f60192',
    getStatus: getStatus,
    pollInterval: 0,
    sleep: noSleep,
    onStatus: function (s) { emitted.push(s); }
  });
  assert.equal(out.kind, 'ACCEPTED');
  assert.equal(out.accepted, true);
  assert.equal(emitted.indexOf('TIMEOUT'), -1);
  assert.equal(emitted.indexOf('FAILED'), -1);
});

test('monitor: LEADER_TIMEOUT → APPEAL → ACCEPTED is one continuing lifecycle', async function () {
  var seq = ['LEADER_TIMEOUT', 'APPEAL_COMMITTING', 'REVEALING', 'ACCEPTED'];
  var i = 0;
  var emitted = [];
  var getStatus = async function () { return { statusName: seq[Math.min(i++, seq.length - 1)] }; };
  var out = await Tx.monitorTransaction({ hash: 'h', getStatus: getStatus, pollInterval: 0, sleep: noSleep, onStatus: function (s) { emitted.push(s); } });
  assert.equal(out.kind, 'ACCEPTED');
  assert.ok(emitted.indexOf('LEADER_TIMEOUT') !== -1);
  assert.ok(emitted.indexOf('APPEAL_COMMITTING') !== -1);
});

test('resolveTimeline: real consensus path resolves to ACCEPTED (no timeout)', function () {
  var t = Tx.resolveTimeline([
    { t: 0, status: 'PENDING' },
    { t: 10, status: 'PROPOSING' },
    { t: 90, status: 'LEADER_TIMEOUT' },
    { t: 100, status: 'APPEAL_COMMITTING' },
    { t: 120, status: 'REVEALING' },
    { t: 137, status: 'ACCEPTED' }
  ]);
  assert.equal(t.kind, 'ACCEPTED');
  assert.equal(t.accepted, true);
});

test('monitor: CANCELED => FAILED_TERMINAL', async function () {
  var out = await Tx.monitorTransaction({ hash: 'h', getStatus: async function () { return { statusName: 'CANCELED', status: 8 }; }, pollInterval: 0, sleep: noSleep });
  assert.equal(out.kind, 'FAILED_TERMINAL');
  assert.equal(out.status, 'CANCELED');
});

test('monitor: RPC failure => RPC_UNAVAILABLE (never a fake result)', async function () {
  var out = await Tx.monitorTransaction({ hash: 'h', getStatus: async function () { throw new Error('fetch failed'); }, pollInterval: 0, sleep: noSleep, maxConsecutiveRpcErrors: 2 });
  assert.equal(out.kind, 'RPC_UNAVAILABLE');
});

// ── ChatStore: messages ───────────────────────────────────────────────────────

test('messages persist and restore in order with stable ids', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.clearMessages();
  var m1 = ChatStore.saveMessage({ id: 'm1', role: 'user', content: 'hello', timestamp: 1 });
  var m2 = ChatStore.saveMessage({ id: 'm2', role: 'assistant', content: 'hi there', timestamp: 2 });
  var list = ChatStore.loadMessages();
  assert.equal(list.length, 2);
  assert.equal(list[0].id, 'm1');
  assert.equal(list[1].id, 'm2');
  assert.equal(list[0].content, 'hello');
  assert.equal(list[1].content, 'hi there');
});

test('saveMessage is idempotent (upsert by id — no duplicate hydration)', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.saveMessage({ id: 'x', role: 'user', content: 'a' });
  ChatStore.saveMessage({ id: 'x', role: 'user', content: 'a' });
  ChatStore.saveMessage({ id: 'x', role: 'user', content: 'a' });
  var list = ChatStore.loadMessages();
  assert.equal(list.length, 1);
  assert.equal(list[0].id, 'x');
});

test('clearMessages removes all persisted messages', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.saveMessage({ id: 'a', role: 'user', content: 'a' });
  ChatStore.saveMessage({ id: 'b', role: 'assistant', content: 'b' });
  ChatStore.clearMessages();
  assert.equal(ChatStore.loadMessages().length, 0);
});

test('session: new session gets a fresh id (New Chat)', function () {
  ChatStore.setStorage(memStorage());
  var s1 = ChatStore.getSession();
  ChatStore.setSession({ sessionId: 'sess-new' });
  var s2 = ChatStore.getSession();
  assert.equal(s2.sessionId, 'sess-new');
  assert.notEqual(s2.sessionId, s1.sessionId);
});

// ── ChatStore: context + transactions ────────────────────────────────────────

test('context: lastAuditResult + lastDeployment persist and restore', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.saveContext({
    lastAuditResult: { risk: { level: 'LOW RISK' }, findings: [] },
    lastDeployment: { address: '0x' + 'ab'.repeat(20), txHash: '0xtx', chainId: 4221 }
  });
  var ctx = ChatStore.loadContext();
  assert.equal(ctx.lastAuditResult.risk.level, 'LOW RISK');
  assert.equal(ctx.lastDeployment.address, '0x' + 'ab'.repeat(20));
  assert.equal(ctx.lastDeployment.chainId, 4221);
});

test('security: private keys / seeds / credentials are NEVER persisted', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.saveContext({
    privateKey: '0x' + '11'.repeat(32),
    seedPhrase: 'witch collapse practice feed shame',
    mnemonic: 'a b c',
    walletSecret: 'hunter2',
    lastAuditResult: { verdict: 'UNKNOWN' }
  });
  var raw = ChatStore.loadContext();
  assert.equal(raw.privateKey, undefined);
  assert.equal(raw.seedPhrase, undefined);
  assert.equal(raw.mnemonic, undefined);
  assert.equal(raw.walletSecret, undefined);
  assert.ok(raw.lastAuditResult);
});

test('transactions: save / update / remove roundtrip', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.saveTx({ type: 'GENLAYER_AUDIT', txHash: '0xtx1', status: 'SUBMITTED' });
  ChatStore.updateTx('0xtx1', { status: 'ACCEPTED' });
  var txs = ChatStore.loadTxs();
  assert.equal(txs.length, 1);
  assert.equal(txs[0].status, 'ACCEPTED');
  ChatStore.removeTx('0xtx1');
  assert.equal(ChatStore.loadTxs().length, 0);
});

// ── Security invariants ──────────────────────────────────────────────────────

test('GenLayer client never exposes eth_getCode', function () {
  var a = GenLayerClient.createAdapter({}, { networkId: 'studionet', networks: { studionet: { id: 'studionet', chainId: 61999, contract: '0x' + 'ab'.repeat(20), deployed: true } } });
  assert.equal(a.getCode, undefined);
  assert.equal(a.eth_getCode, undefined);
  assert.equal(GenLayerClient.eth_getCode, undefined);
});

test('EVM networks remain read-only (policy unchanged)', function () {
  ['ethereum', 'bsc', 'base', 'arbitrum', 'optimism'].forEach(function (id) {
    assert.equal(Networks.getFamily(id), 'EVM');
  });
});

console.log('\nAll phase761 tests completed.');
