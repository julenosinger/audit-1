// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer Transaction Lifecycle + State Engine (Phase 7.6.2)
//
// The SINGLE transaction-state engine for real GenLayer transactions. Chat and
// result cards are two views of the SAME state produced here — they must never
// hold independent lifecycles.
//
// ONE REAL TRANSACTION → ONE ENGINE → ONE LIFECYCLE → { CHAT, CARD } → PERSIST
//
// The engine NEVER infers status from elapsed time. It polls the REAL GenLayer
// transaction status and only resolves when the chain reports a terminal state.
// A local JavaScript timer can never mark a live transaction as failed.
//
// Responsibilities:
//   normalizeStatus      — map numeric/string SDK status → canonical name
//   classify             — PROCESSING / CONTINUING_* / ACCEPTED / FINALIZED /
//                          FAILED_TERMINAL / UNKNOWN
//   statusMessage        — honest, contextual UI copy per real status
//   statusEmoji          — compact emoji per status (chat rendering)
//   track / update / state / list / subscribe — in-memory state registry
//   monitorTransaction   — poll real status until a terminal state; updates the
//                          state registry and notifies subscribers
//   resolveTimeline      — pure timeline resolver (regression tests)
//   eventKey             — deterministic event-message id (no duplicates)
//
// Works in browser and Node (tests). getStatus / sleep are injectable.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerTx = api;
})(function () {
  'use strict';

  var STATUS_NUMBER_TO_NAME = {
    '0': 'UNINITIALIZED',
    '1': 'PENDING',
    '2': 'PROPOSING',
    '3': 'COMMITTING',
    '4': 'REVEALING',
    '5': 'ACCEPTED',
    '6': 'UNDETERMINED',
    '7': 'FINALIZED',
    '8': 'CANCELED',
    '9': 'APPEAL_REVEALING',
    '10': 'APPEAL_COMMITTING',
    '11': 'READY_TO_FINALIZE',
    '12': 'VALIDATORS_TIMEOUT',
    '13': 'LEADER_TIMEOUT'
  };

  var STATUS_NAMES = [
    'UNINITIALIZED', 'PENDING', 'PROPOSING', 'COMMITTING', 'REVEALING',
    'ACCEPTED', 'UNDETERMINED', 'FINALIZED', 'CANCELED',
    'APPEAL_REVEALING', 'APPEAL_COMMITTING', 'READY_TO_FINALIZE',
    'VALIDATORS_TIMEOUT', 'LEADER_TIMEOUT'
  ];

  // Statuses that keep the transaction alive (must continue polling).
  var PROCESSING = ['UNINITIALIZED', 'PENDING', 'PROPOSING', 'COMMITTING', 'REVEALING'];
  var APPEALING = ['APPEAL_REVEALING', 'APPEAL_COMMITTING', 'READY_TO_FINALIZE'];
  var TIMEOUTS = ['LEADER_TIMEOUT', 'VALIDATORS_TIMEOUT'];

  // Success terminal states (result is recoverable here).
  var SUCCESS = ['ACCEPTED', 'FINALIZED'];
  // Failure terminal states (no result; chain decided against the tx).
  var FAILED_TERMINAL = ['CANCELED', 'UNDETERMINED'];

  // Compact emoji for chat rendering (matches the UI copy in statusMessage).
  var STATUS_EMOJI = {
    UNINITIALIZED: '·',
    PENDING: '⏳',
    PROPOSING: '🔄',
    COMMITTING: '🔐',
    REVEALING: '👁',
    ACCEPTED: '✅',
    UNDETERMINED: '❓',
    FINALIZED: '✅',
    CANCELED: '❌',
    APPEAL_REVEALING: '↩️',
    APPEAL_COMMITTING: '↩️',
    READY_TO_FINALIZE: '⏳',
    VALIDATORS_TIMEOUT: '⚠️',
    LEADER_TIMEOUT: '⚠️'
  };

  function normalizeStatus(status) {
    if (status === null || status === undefined) return 'UNKNOWN';
    if (typeof status === 'number') return STATUS_NUMBER_TO_NAME[String(status)] || 'UNKNOWN';
    if (typeof status === 'string') {
      var s = String(status).trim().toUpperCase();
      if (STATUS_NAMES.indexOf(s) !== -1) return s;
      if (STATUS_NUMBER_TO_NAME[String(status)] !== undefined) return STATUS_NUMBER_TO_NAME[String(status)];
      return 'UNKNOWN';
    }
    return 'UNKNOWN';
  }

  function classify(status) {
    var s = normalizeStatus(status);
    if (s === 'ACCEPTED') return { kind: 'ACCEPTED', terminal: true, accepted: true, finalized: false, status: s };
    if (s === 'FINALIZED') return { kind: 'FINALIZED', terminal: true, accepted: true, finalized: true, status: s };
    if (FAILED_TERMINAL.indexOf(s) !== -1) return { kind: 'FAILED_TERMINAL', terminal: true, accepted: false, finalized: false, status: s };
    if (TIMEOUTS.indexOf(s) !== -1) return { kind: 'CONTINUING_TIMEOUT', terminal: false, accepted: false, finalized: false, status: s };
    if (APPEALING.indexOf(s) !== -1) return { kind: 'CONTINUING_APPEAL', terminal: false, accepted: false, finalized: false, status: s };
    if (PROCESSING.indexOf(s) !== -1) return { kind: 'PROCESSING', terminal: false, accepted: false, finalized: false, status: s };
    return { kind: 'UNKNOWN', terminal: false, accepted: false, finalized: false, status: s };
  }

  function isAccepted(status) { return normalizeStatus(status) === 'ACCEPTED'; }
  function isFinalized(status) { return normalizeStatus(status) === 'FINALIZED'; }
  function isTerminalFailure(status) { return FAILED_TERMINAL.indexOf(normalizeStatus(status)) !== -1; }
  function isContinuing(status) { return !classify(status).terminal; }

  function statusEmoji(status) {
    var s = normalizeStatus(status);
    return STATUS_EMOJI[s] || '·';
  }

  function statusMessage(status) {
    switch (normalizeStatus(status)) {
      case 'UNINITIALIZED': return 'GenLayer transaction initialized.';
      case 'PENDING': return 'Transaction submitted to GenLayer.';
      case 'PROPOSING': return 'Leader is proposing the transaction.';
      case 'COMMITTING': return 'Validators are committing their votes.';
      case 'REVEALING': return 'Validators are revealing their votes.';
      case 'LEADER_TIMEOUT': return 'Leader timeout detected — GenLayer is continuing the transaction through its consensus mechanism.';
      case 'VALIDATORS_TIMEOUT': return 'Validators timeout detected — GenLayer is continuing the transaction through its consensus mechanism.';
      case 'APPEAL_COMMITTING': return 'Appeal round in progress — validators are committing.';
      case 'APPEAL_REVEALING': return 'Appeal round in progress — validators are revealing.';
      case 'READY_TO_FINALIZE': return 'GenLayer transaction ready to finalize.';
      case 'ACCEPTED': return 'Transaction accepted by GenLayer. Waiting for finality.';
      case 'FINALIZED': return 'Transaction finalized by GenLayer.';
      case 'CANCELED': return 'GenLayer transaction canceled.';
      case 'UNDETERMINED': return 'GenLayer could not determine a final consensus result.';
      case 'RPC_UNAVAILABLE': return 'Unable to reach the GenLayer RPC. The transaction may still be processing.';
      default: return 'GenLayer transaction processing.';
    }
  }

  // ── In-memory state registry (single source of state for Chat + Card) ──────
  var _states = {};
  var _listeners = [];

  function track(state) {
    if (!state || !state.txHash) return state;
    var prev = _states[state.txHash] || {};
    var now = Date.now();
    var status = normalizeStatus(state.lifecycleState || state.status);
    var merged = Object.assign({}, prev, state, {
      txHash: state.txHash,
      status: status,
      lifecycleState: status,
      lastUpdatedAt: state.lastUpdatedAt || now
    });
    if (status === 'ACCEPTED' && !merged.acceptedAt) merged.acceptedAt = now;
    if (status === 'FINALIZED' && !merged.finalizedAt) merged.finalizedAt = now;
    _states[state.txHash] = merged;
    _emit(merged);
    return merged;
  }

  function update(txHash, patch) {
    var cur = _states[txHash] || { txHash: txHash };
    var next = Object.assign({}, cur, patch || {}, { txHash: txHash });
    // Keep status and lifecycleState in sync when only one is provided.
    if (patch && patch.status !== undefined && patch.lifecycleState === undefined) next.lifecycleState = patch.status;
    if (patch && patch.lifecycleState !== undefined && patch.status === undefined) next.status = patch.lifecycleState;
    return track(next);
  }

  function state(txHash) { return _states[txHash] || null; }
  function list() { return Object.keys(_states).map(function (k) { return _states[k]; }); }
  function resetStates() { _states = {}; }

  function subscribe(fn) { if (typeof fn === 'function') _listeners.push(fn); }
  function unsubscribe(fn) { _listeners = _listeners.filter(function (f) { return f !== fn; }); }
  function _emit(state) {
    for (var i = 0; i < _listeners.length; i++) { try { _listeners[i](state); } catch (e) {} }
  }

  // Deterministic event-message id (no duplicate events after refresh).
  function eventKey(txHash, eventId) {
    return 'tx:' + String(txHash) + ':event:' + String(eventId);
  }
  function progressKey(txHash) {
    return 'transaction-progress:' + String(txHash);
  }

  // Poll the REAL transaction status until a terminal state. Updates the state
  // registry (when opts.meta.txHash is set) and notifies subscribers on every
  // change. Never uses elapsed time to declare failure.
  async function monitorTransaction(opts) {
    opts = opts || {};
    var hash = opts.hash;
    var getStatus = opts.getStatus;
    var onStatus = opts.onStatus || function () {};
    var pollInterval = (opts.pollInterval === undefined) ? 2000 : opts.pollInterval;
    var sleep = opts.sleep || function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    var maxConsecutiveRpcErrors = opts.maxConsecutiveRpcErrors || 30;
    var maxAttempts = opts.maxAttempts || 0; // 0 = unlimited (consensus is unbounded)
    var meta = opts.meta || null;
    // 'ACCEPTED' (default) resolves as soon as the result is recoverable;
    // 'FINALIZED' keeps polling through ACCEPTED until finality (on-chain claim).
    var until = opts.until === 'FINALIZED' ? 'FINALIZED' : 'ACCEPTED';

    if (typeof getStatus !== 'function') {
      return { ok: false, kind: 'RPC_UNAVAILABLE', status: 'UNKNOWN', error: 'NO_STATUS_PROVIDER', hash: hash };
    }

    if (meta && meta.txHash) {
      track(Object.assign({}, meta, { status: 'PENDING', lifecycleState: 'PENDING', submittedAt: meta.submittedAt || Date.now(), lastUpdatedAt: Date.now() }));
    }

    var attempts = 0;
    var rpcErrors = 0;
    var lastStatus = 'UNINITIALIZED';
    while (true) {
      var tx = null, rpcError = null;
      try { tx = await getStatus(hash); }
      catch (e) { rpcError = e; }

      if (rpcError) {
        rpcErrors += 1;
        onStatus('RPC_UNAVAILABLE', { detail: String((rpcError && rpcError.message) || rpcError), hash: hash });
        if (meta && meta.txHash) update(meta.txHash, { status: 'RPC_UNAVAILABLE', lastUpdatedAt: Date.now() });
        if (rpcErrors >= maxConsecutiveRpcErrors) {
          return { ok: false, kind: 'RPC_UNAVAILABLE', status: 'UNKNOWN', error: 'GENLAYER_RPC_UNAVAILABLE', hash: hash };
        }
        await sleep(pollInterval);
        continue;
      }
      rpcErrors = 0;
      attempts += 1;

      var status = tx && (tx.statusName || tx.status);
      var name = normalizeStatus(status);
      var cls = classify(name);
      lastStatus = name;
      onStatus(name, { status: name, tx: tx, hash: hash });
      if (meta && meta.txHash) update(meta.txHash, { status: name, lifecycleState: name, lastUpdatedAt: Date.now() });

      if (cls.kind === 'ACCEPTED') {
        if (until === 'FINALIZED') {
          // Intermediate step on the way to finality — keep polling.
          await sleep(pollInterval);
          continue;
        }
        return { ok: true, kind: 'ACCEPTED', status: name, accepted: true, finalized: false, tx: tx, hash: hash };
      }
      if (cls.kind === 'FINALIZED') return { ok: true, kind: 'FINALIZED', status: name, accepted: true, finalized: true, tx: tx, hash: hash };
      if (cls.kind === 'FAILED_TERMINAL') return { ok: true, kind: 'FAILED_TERMINAL', status: name, accepted: false, finalized: false, tx: tx, hash: hash };

      if (maxAttempts > 0 && attempts >= maxAttempts) {
        return { ok: false, kind: 'STILL_PROCESSING', status: name, accepted: false, finalized: false, tx: tx, hash: hash };
      }

      await sleep(pollInterval);
    }
  }

  // Deterministic timeline resolver (pure). Given ordered events
  // [{ t, status }], returns the outcome the monitor WOULD reach — proving that
  // no local timer interrupts a still-progressing transaction.
  function resolveTimeline(events) {
    events = events || [];
    var outcome = { status: 'UNINITIALIZED', kind: 'PROCESSING', accepted: false, finalized: false, sawTimeout: false, steps: [] };
    for (var i = 0; i < events.length; i++) {
      var name = normalizeStatus(events[i].status);
      var cls = classify(name);
      outcome.steps.push({ t: events[i].t, status: name, kind: cls.kind });
      if (cls.kind === 'ACCEPTED') { outcome.kind = 'ACCEPTED'; outcome.status = name; outcome.accepted = true; return outcome; }
      if (cls.kind === 'FINALIZED') { outcome.kind = 'FINALIZED'; outcome.status = name; outcome.accepted = true; outcome.finalized = true; return outcome; }
      if (cls.kind === 'FAILED_TERMINAL') { outcome.kind = 'FAILED_TERMINAL'; outcome.status = name; return outcome; }
      outcome.status = name;
      outcome.kind = cls.kind;
    }
    return outcome;
  }

  return {
    STATUS_NUMBER_TO_NAME: STATUS_NUMBER_TO_NAME,
    STATUS_NAMES: STATUS_NAMES,
    PROCESSING: PROCESSING,
    APPEALING: APPEALING,
    TIMEOUTS: TIMEOUTS,
    SUCCESS: SUCCESS,
    FAILED_TERMINAL: FAILED_TERMINAL,
    STATUS_EMOJI: STATUS_EMOJI,
    normalizeStatus: normalizeStatus,
    classify: classify,
    isAccepted: isAccepted,
    isFinalized: isFinalized,
    isTerminalFailure: isTerminalFailure,
    isContinuing: isContinuing,
    statusEmoji: statusEmoji,
    statusMessage: statusMessage,
    track: track,
    update: update,
    state: state,
    list: list,
    resetStates: resetStates,
    subscribe: subscribe,
    unsubscribe: unsubscribe,
    eventKey: eventKey,
    progressKey: progressKey,
    monitorTransaction: monitorTransaction,
    resolveTimeline: resolveTimeline
  };
});
