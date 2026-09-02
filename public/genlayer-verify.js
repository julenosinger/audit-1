// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — On-Chain State Verifier (Phase 7.7)
//
// The SINGLE source of truth for deciding whether a visible publish/adjudicate
// action is actually confirmed on-chain. A UI action must NEVER be labeled
// "ON-CHAIN" unless this module returns VERIFIED_ON_CHAIN.
//
// FINALIZED is necessary but NOT sufficient: after the transaction reaches
// FINALIZED, the contract state is read and compared against the submitted
// operation. Only a matching, real contract state produces VERIFIED_ON_CHAIN.
//
// Responsibilities:
//   verifyFinalizedOnChainState — the centralized verification entry point
//   parseGetAudit              — parse the contract's "score|verdict|summary"
//   explorerTxUrl / explorerBaseUrl — real, confirmed Explorer routing
//
// Works in browser and Node (tests). No network, no wallet, no secrets.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerVerify = api;
})(function () {
  'use strict';

  var STATUS = {
    VERIFIED_ON_CHAIN: 'VERIFIED_ON_CHAIN',
    PARTIAL_VERIFICATION: 'PARTIAL_VERIFICATION',
    VERIFICATION_PENDING: 'VERIFICATION_PENDING',
    VERIFICATION_FAILED: 'VERIFICATION_FAILED',
    OFF_CHAIN: 'OFF_CHAIN',
    FAILED: 'FAILED'
  };

  var VALID_VERDICTS = ['SAFE', 'WARNING', 'DANGER'];

  // Confirmed Bradbury Explorer routing (from the explorer router config:
  // path "/tx/:hash"). Studionet has no public explorer.
  var EXPLORER_BASE = {
    bradbury: 'https://explorer-bradbury.genlayer.com/'
  };

  function explorerBaseUrl(networkId) {
    return EXPLORER_BASE[networkId] || null;
  }

  // Resolve the transaction-specific Explorer URL for a REAL transaction hash.
  // Never fabricates a URL and never falls back to a homepage link silently.
  function explorerTxUrl(networkId, txHash) {
    if (!txHash || typeof txHash !== 'string') return null;
    var base = explorerBaseUrl(networkId);
    if (!base) return null;
    // Only a 0x… hash produces a transaction-specific URL.
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash).trim())) return null;
    return base + 'tx/' + String(txHash).trim();
  }

  // Resolve the address/contract detail URL (confirmed route /address/:address).
  function explorerAddressUrl(networkId, address) {
    if (!address || typeof address !== 'string') return null;
    var base = explorerBaseUrl(networkId);
    if (!base) return null;
    if (!/^0x[0-9a-fA-F]{40}$/.test(String(address).trim())) return null;
    return base + 'address/' + String(address).trim();
  }

  function normalizeAddr(a) {
    return (typeof a === 'string') ? a.trim().toLowerCase() : '';
  }

  function normalizeScore(s) {
    if (s === null || s === undefined) return null;
    var n = parseInt(String(s).trim(), 10);
    if (isNaN(n)) return null;
    return n;
  }

  function normalizeVerdict(v) {
    return String(v || '').trim().toUpperCase();
  }

  // Parse the AuditAI get_audit() return value "score|verdict|summary".
  function parseGetAudit(raw) {
    if (typeof raw !== 'string' || !raw) return null;
    var parts = raw.split('|');
    if (parts.length < 2) return null;
    return { score: parts[0], verdict: parts[1], summary: parts.slice(2).join('|') };
  }

  function _check(cond, field, matched, mismatch) {
    if (cond) matched.push(field); else mismatch.push(field);
  }

  // publish_audit is deterministic: the stored record must match the submitted
  // score / verdict / findings exactly.
  function verifyPublishAudit(expected, state) {
    var matched = [], mismatch = [];
    var rec = parseGetAudit(state.getAudit);
    if (!rec) return { status: STATUS.VERIFICATION_PENDING, matched: matched, mismatch: mismatch };

    var expScore = normalizeScore(expected.score);
    if (expScore !== null) {
      _check(normalizeScore(rec.score) === expScore, 'score', matched, mismatch);
    }
    var expVerdict = normalizeVerdict(expected.verdict);
    if (expVerdict) {
      _check(normalizeVerdict(rec.verdict) === expVerdict, 'verdict', matched, mismatch);
    }
    if (expected.findings !== undefined && expected.findings !== null) {
      _check(String(rec.summary) === String(expected.findings), 'findings', matched, mismatch);
    }
    if (expected.submittedBy && state.getAuthor !== undefined && state.getAuthor !== null &&
        /^0x[0-9a-fA-F]{40}$/.test(String(state.getAuthor).trim())) {
      _check(normalizeAddr(state.getAuthor) === normalizeAddr(expected.submittedBy), 'author', matched, mismatch);
    }

    return {
      status: mismatch.length === 0 ? STATUS.VERIFIED_ON_CHAIN : STATUS.VERIFICATION_FAILED,
      matched: matched,
      mismatch: mismatch
    };
  }

  // analyze_and_publish produces an LLM-generated summary: the stored record
  // cannot be matched against the input context. The maximum the contract
  // permits is verifying that a well-formed record actually exists.
  function verifyAnalyzeAndPublish(expected, state) {
    var matched = [], mismatch = [];
    var rec = parseGetAudit(state.getAudit);
    if (!rec) return { status: STATUS.VERIFICATION_PENDING, matched: matched, mismatch: mismatch };

    var score = normalizeScore(rec.score);
    _check(score !== null && score >= 0 && score <= 100, 'score', matched, mismatch);
    _check(VALID_VERDICTS.indexOf(normalizeVerdict(rec.verdict)) !== -1, 'verdict', matched, mismatch);
    _check(typeof rec.summary === 'string' && rec.summary.trim().length > 0, 'summary', matched, mismatch);

    return {
      status: mismatch.length === 0 ? STATUS.VERIFIED_ON_CHAIN : STATUS.VERIFICATION_FAILED,
      matched: matched,
      mismatch: mismatch
    };
  }

  // ── Centralized verification entry point ───────────────────────────────────
  // opts: { action, txHash, contractAddress, networkId, chainId, submittedBy, expected, state }
  //   action: 'publish_audit' | 'analyze_and_publish' | 'analyze_evidence'
  //   expected: { score, verdict, findings, submittedBy }
  //   state: { getAudit, getAuthor } (raw read results)
  // Returns { verified, status, txHash, ..., matchedFields, mismatchFields, verifiedAt }
  function verifyFinalizedOnChainState(opts) {
    opts = opts || {};
    var action = opts.action || '';
    var state = opts.state || {};
    var expected = opts.expected || {};

    var result = {
      verified: false,
      status: STATUS.VERIFICATION_PENDING,
      txHash: opts.txHash || null,
      contractAddress: opts.contractAddress || null,
      networkId: opts.networkId || null,
      chainId: opts.chainId || null,
      state: state,
      matchedFields: [],
      mismatchFields: [],
      verifiedAt: null
    };

    // No contract state read at all → cannot verify.
    if (state.getAudit === undefined || state.getAudit === null) {
      return result;
    }

    var v;
    if (action === 'publish_audit') {
      v = verifyPublishAudit(expected, state);
    } else if (action === 'analyze_and_publish') {
      v = verifyAnalyzeAndPublish(expected, state);
    } else {
      result.status = STATUS.VERIFICATION_FAILED;
      result.mismatchFields = ['unknown_action:' + action];
      return result;
    }

    result.status = v.status;
    result.matchedFields = v.matched;
    result.mismatchFields = v.mismatch;
    result.verified = (v.status === STATUS.VERIFIED_ON_CHAIN);
    if (result.verified) result.verifiedAt = Date.now();
    return result;
  }

  return {
    STATUS: STATUS,
    VALID_VERDICTS: VALID_VERDICTS,
    EXPLORER_BASE: EXPLORER_BASE,
    explorerBaseUrl: explorerBaseUrl,
    explorerTxUrl: explorerTxUrl,
    explorerAddressUrl: explorerAddressUrl,
    normalizeAddr: normalizeAddr,
    normalizeScore: normalizeScore,
    normalizeVerdict: normalizeVerdict,
    parseGetAudit: parseGetAudit,
    verifyFinalizedOnChainState: verifyFinalizedOnChainState
  };
});
