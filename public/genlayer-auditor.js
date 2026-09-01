// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer AI Auditor adapter (Phase 5)
//
// Bridges the deterministic Local Audit Engine and the GenLayer Intelligent
// Contract's semantic layer. Responsibilities:
//   buildPayload     — deterministic, versioned, reproducible evidence package
//   validateResponse — schema + enum + evidence-reference (hallucination) guard
//   mergeResults     — evidence reconciliation (local vs GenLayer)
//   analyze          — orchestrate request/validate/merge with timeout + status
//
// This module contains NO security rules and NEVER invents findings. It only
// passes local evidence and validates/merges the GenLayer response.
// Works in browser and Node (for unit tests). The GenLayer client is injected.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerAuditor = api;
})(function () {
  'use strict';

  var VERSION = '6.0.0';

  var VALID_SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var VALID_CONFIDENCE = ['HIGH', 'MEDIUM', 'LOW'];
  var VALID_VERDICTS = [
    'NO_CONFIRMED_VULNERABILITY',
    'POTENTIAL_VULNERABILITY',
    'LIKELY_VULNERABILITY',
    'CONFIRMED_VULNERABILITY',
    'NEEDS_REVIEW'
  ];
  var VALID_STATUS = ['NOT_REQUESTED', 'PENDING', 'ACCEPTED', 'FINALIZED', 'FAILED', 'TIMEOUT', 'INVALID'];
  var VALID_CATEGORIES = [
    'reentrancy', 'access-control', 'mint', 'pause', 'blacklist', 'whitelist',
    'fees', 'proxy', 'ownership', 'selfdestruct', 'tx-origin', 'external-call',
    'token', 'bytecode', 'storage', 'other'
  ];

  var RISK_RANK = {
    'LIMITED ANALYSIS': 0,
    'LOW RISK': 1,
    'MODERATE RISK': 2,
    'HIGH RISK': 3,
    'CRITICAL RISK': 4
  };

  function buildPayload(result) {
    if (result && result.payload) return result.payload;
    return {
      version: VERSION,
      analysisVersion: result && result.analysisVersion,
      network: result ? result.networkId : null,
      networkName: result ? result.networkName : null,
      chainId: result ? result.chainId : null,
      contract: result ? result.contract : {},
      analysis: {},
      findings: result ? result.findings : []
    };
  }

  function collectIds(payload) {
    var ids = {};
    var eg = payload && payload.analysis && payload.analysis.evidenceGraph;
    (eg && eg.nodes || []).forEach(function (n) { ids[n.id] = true; });
    (payload && payload.findings || []).forEach(function (f) { ids[f.id] = true; });
    return ids;
  }

  function validateResponse(resp, payload) {
    if (!resp || typeof resp !== 'object' || Array.isArray(resp)) {
      return { valid: false, errors: ['response is not an object'] };
    }
    var errors = [];
    if (VALID_VERDICTS.indexOf(resp.verdict) === -1) errors.push('invalid verdict: ' + resp.verdict);
    if (VALID_CONFIDENCE.indexOf(resp.confidence) === -1) errors.push('invalid confidence: ' + resp.confidence);
    if (resp.findings !== undefined && !Array.isArray(resp.findings)) errors.push('findings must be an array');
    if (resp.globalAssessment !== undefined && (typeof resp.globalAssessment !== 'object' || resp.globalAssessment === null)) errors.push('globalAssessment must be an object');

    var evidenceIds = collectIds(payload);
    if (Array.isArray(resp.findings)) {
      resp.findings.forEach(function (f, i) {
        if (!f || typeof f !== 'object') { errors.push('finding ' + i + ' is not an object'); return; }
        if (!f.id) errors.push('finding ' + i + ' missing id');
        if (VALID_SEVERITY.indexOf(f.severity) === -1) errors.push('finding ' + i + ' invalid severity: ' + f.severity);
        if (VALID_CONFIDENCE.indexOf(f.confidence) === -1) errors.push('finding ' + i + ' invalid confidence: ' + f.confidence);
        if (f.category && VALID_CATEGORIES.indexOf(f.category) === -1) errors.push('finding ' + i + ' invalid category: ' + f.category);
        (f.evidenceRefs || []).forEach(function (ref) {
          if (!evidenceIds[ref]) errors.push('INVALID_AI_EVIDENCE_REFERENCE: ' + ref);
        });
      });
    }
    return { valid: errors.length === 0, errors: errors };
  }

  function rank(level) { return RISK_RANK[level] !== undefined ? RISK_RANK[level] : 0; }

  function isMoreSevere(a, b) { return rank(a) > rank(b); }

  // Bump local level by one notch (used for REVIEW_REQUIRED).
  function bump(level) {
    if (level === 'LOW RISK') return 'MODERATE RISK';
    if (level === 'MODERATE RISK') return 'HIGH RISK';
    if (level === 'HIGH RISK') return 'CRITICAL RISK';
    return 'CRITICAL RISK';
  }

  // Local support: any local finding of MEDIUM+ that overlaps the GenLayer categories.
  function hasLocalSupport(localResult, glResponse) {
    var cats = (glResponse.findings || []).map(function (f) { return f.category; });
    var localCats = {};
    (localResult && localResult.findings || []).forEach(function (f) {
      if (f.severity === 'MEDIUM' || f.severity === 'HIGH' || f.severity === 'CRITICAL') localCats[f.category] = true;
    });
    return cats.some(function (c) { return localCats[c]; });
  }

  function mergeResults(localResult, glResponse) {
    var localLevel = localResult && localResult.risk ? localResult.risk.level : 'UNKNOWN';
    var glLevel = glResponse && glResponse.globalAssessment && glResponse.globalAssessment.riskLevel ? glResponse.globalAssessment.riskLevel : 'UNKNOWN';
    var status = 'RESOLVED';
    var finalLevel = localLevel;

    if (glResponse && glResponse.verdict) {
      if (isMoreSevere(glLevel, localLevel)) {
        if (glResponse.confidence === 'HIGH' && hasLocalSupport(localResult, glResponse)) {
          finalLevel = glLevel;
          status = 'RESOLVED';
        } else {
          finalLevel = bump(localLevel);
          status = 'REVIEW_REQUIRED';
        }
      }
      // GenLayer can only *increase* confidence/interpretation, never erase local evidence.
      // Lower/equal GenLayer severity keeps the local level.
    }

    return {
      local: { risk: localLevel },
      genlayer: glResponse,
      final: {
        risk: finalLevel,
        confidence: glResponse ? glResponse.confidence : 'LOW',
        status: status,
        rationale: status === 'REVIEW_REQUIRED'
          ? 'GenLayer suggests higher severity than local evidence without HIGH-confidence local support — review required.'
          : (glResponse ? 'GenLayer interpretation reconciled with local evidence.' : 'Local analysis only.'),
        evidence: localResult ? localResult.findings : []
      }
    };
  }

  function withTimeout(promise, ms) {
    return new Promise(function (resolve, reject) {
      var done = false;
      var t = setTimeout(function () { if (!done) { done = true; resolve('TIMEOUT'); } }, ms);
      promise.then(function (v) { if (!done) { done = true; clearTimeout(t); resolve(v); } },
        function (e) { if (!done) { done = true; clearTimeout(t); reject(e); } });
    });
  }

  function doRequest(client, payload, opts) {
    if (!client) return Promise.resolve(null);
    if (typeof client.analyzeEvidence === 'function') return Promise.resolve(client.analyzeEvidence(payload, opts));
    if (typeof client.write === 'function') return Promise.resolve(client.write(payload));
    return Promise.reject(new Error('client does not implement analyzeEvidence/write'));
  }

  function emit(opts, state, detail) {
    if (opts && typeof opts.onStatus === 'function') {
      try { opts.onStatus(state, detail); } catch (e) {}
    }
  }

  async function analyze(client, result, opts) {
    opts = opts || {};
    var payload = buildPayload(result);
    var timeoutMs = opts.timeoutMs || 90000;
    if (!client) {
      emit(opts, 'FAILED', 'GENLAYER_UNAVAILABLE');
      return { status: 'FAILED', error: 'GENLAYER_UNAVAILABLE', payload: payload, local: result, genlayer: null };
    }
    try {
      var resp = await withTimeout(doRequest(client, payload, opts), timeoutMs);
      if (resp === 'TIMEOUT') { emit(opts, 'TIMEOUT'); return { status: 'TIMEOUT', payload: payload, local: result, genlayer: null }; }
      if (resp === null) { emit(opts, 'FAILED', 'GENLAYER_UNAVAILABLE'); return { status: 'FAILED', error: 'GENLAYER_UNAVAILABLE', payload: payload, local: result, genlayer: null }; }
      emit(opts, 'VALIDATING');
      var v = validateResponse(resp, payload);
      if (!v.valid) { emit(opts, 'INVALID', v.errors); return { status: 'INVALID', errors: v.errors, payload: payload, local: result, genlayer: null }; }
      emit(opts, 'VALIDATED');
      return { status: 'FINALIZED', payload: payload, local: result, genlayer: resp, merged: mergeResults(result, resp) };
    } catch (e) {
      var code = (e && e.message) || 'GENLAYER_ERROR';
      emit(opts, 'FAILED', code);
      return { status: 'FAILED', error: code, detail: (e && e.detail) || null, payload: payload, local: result, genlayer: null };
    }
  }

  return {
    VERSION: VERSION,
    VALID_SEVERITY: VALID_SEVERITY,
    VALID_CONFIDENCE: VALID_CONFIDENCE,
    VALID_VERDICTS: VALID_VERDICTS,
    VALID_STATUS: VALID_STATUS,
    VALID_CATEGORIES: VALID_CATEGORIES,
    buildPayload: buildPayload,
    validateResponse: validateResponse,
    mergeResults: mergeResults,
    analyze: analyze
  };
});
