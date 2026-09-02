// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer Transaction Lifecycle (Phase 7.6.1)
//
// The single transaction-status state machine + monitor for real GenLayer
// transactions. GenLayer consensus is an asynchronous on-chain job: a
// transaction can legitimately remain in PROPOSING/COMMITTING/REVEALING (or go
// through LEADER_TIMEOUT / appeal rounds) far beyond any fixed local timer.
//
// This module therefore NEVER infers status from elapsed time. It polls the
// REAL transaction status and only resolves when the chain reports a terminal
// state. A local JavaScript timer can never mark a live transaction as failed.
//
// Responsibilities:
//   normalizeStatus      — map numeric/string SDK status → canonical name
//   classify             — PROCESSING / CONTINUING_* / ACCEPTED / FINALIZED /
//                          FAILED_TERMINAL / UNKNOWN
//   statusMessage        — honest, contextual UI copy per real status
//   monitorTransaction   — poll real status until a terminal state
//
// Works in browser and Node (tests). getStatus is injected so tests can drive a
// deterministic timeline (e.g. the 90s/137s regression) without waiting.
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

  // Classify a real status into a lifecycle kind. This is the single source of
  // truth for "what does this status mean" — LEADER_TIMEOUT / VALIDATORS_TIMEOUT
  // are CONTINUING (the network can still progress through an appeal), never a
  // terminal failure.
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
  function isContinuing(status) {
    var c = classify(status);
    return !c.terminal;
  }

  // Honest, contextual UI copy per real status. Never claims a timeout/failure
  // unless the chain actually reports one.
  function statusMessage(status) {
    switch (normalizeStatus(status)) {
      case 'UNINITIALIZED': return 'GenLayer transaction initialized.';
      case 'PENDING': return 'GenLayer analysis submitted — waiting for consensus.';
      case 'PROPOSING': return 'GenLayer consensus: leader proposing.';
      case 'COMMITTING': return 'GenLayer consensus: validators committing.';
      case 'REVEALING': return 'GenLayer consensus: validators revealing.';
      case 'LEADER_TIMEOUT': return 'Leader timeout detected — GenLayer is continuing through the consensus/appeal process.';
      case 'VALIDATORS_TIMEOUT': return 'Validators timeout detected — GenLayer is continuing through the consensus/appeal process.';
      case 'APPEAL_COMMITTING': return 'Appeal round in progress — validators are committing.';
      case 'APPEAL_REVEALING': return 'Appeal round in progress — validators are revealing.';
      case 'READY_TO_FINALIZE': return 'GenLayer analysis ready to finalize.';
      case 'ACCEPTED': return 'GenLayer analysis accepted — consensus reached. Waiting for finality.';
      case 'FINALIZED': return 'GenLayer analysis finalized.';
      case 'CANCELED': return 'GenLayer transaction canceled.';
      case 'UNDETERMINED': return 'GenLayer could not determine a final consensus result.';
      case 'RPC_UNAVAILABLE': return 'Unable to reach the GenLayer RPC. The transaction may still be processing.';
      default: return 'GenLayer transaction processing.';
    }
  }

  // Poll the REAL transaction status until a terminal state. Never uses elapsed
  // time to declare failure. `getStatus` is injected (defaults to a client
  // getTransaction) and returns a transaction object with `status` and/or
  // `statusName`. `sleep` and `onStatus` are injectable for tests.
  async function monitorTransaction(opts) {
    opts = opts || {};
    var hash = opts.hash;
    var getStatus = opts.getStatus;
    var onStatus = opts.onStatus || function () {};
    var pollInterval = (opts.pollInterval === undefined) ? 2000 : opts.pollInterval;
    var sleep = opts.sleep || function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
    var maxConsecutiveRpcErrors = opts.maxConsecutiveRpcErrors || 30;
    var maxAttempts = opts.maxAttempts || 0; // 0 = unlimited (consensus is unbounded)

    if (typeof getStatus !== 'function') {
      return { ok: false, kind: 'RPC_UNAVAILABLE', status: 'UNKNOWN', error: 'NO_STATUS_PROVIDER', hash: hash };
    }

    var attempts = 0;
    var rpcErrors = 0;
    while (true) {
      var tx = null, rpcError = null;
      try { tx = await getStatus(hash); }
      catch (e) { rpcError = e; }

      if (rpcError) {
        rpcErrors += 1;
        onStatus('RPC_UNAVAILABLE', { detail: String((rpcError && rpcError.message) || rpcError), hash: hash });
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
      onStatus(name, { status: name, tx: tx, hash: hash });

      if (cls.kind === 'ACCEPTED') return { ok: true, kind: 'ACCEPTED', status: name, accepted: true, finalized: false, tx: tx, hash: hash };
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
    normalizeStatus: normalizeStatus,
    classify: classify,
    isAccepted: isAccepted,
    isFinalized: isFinalized,
    isTerminalFailure: isTerminalFailure,
    isContinuing: isContinuing,
    statusMessage: statusMessage,
    monitorTransaction: monitorTransaction,
    resolveTimeline: resolveTimeline
  };
});
