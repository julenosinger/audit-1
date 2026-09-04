// ═══════════════════════════════════════════════════════════════════════════════
// forgeContract — Nemotron client (Phase 8)
//
// Thin client for the secure /api/chat proxy. It holds NO credentials and never
// executes actions. It normalizes and validates the model's structured output so
// the application never routes on arbitrary AI prose.
//
// Pure logic (no DOM, no fetch except the injectable `request` helper), testable
// in Node. Works in browser and Node.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAINemotronClient = api;
})(function () {
  'use strict';

  var ENDPOINT = '/api/chat';

  // ── Deterministic error taxonomy (never expose raw provider errors) ─────────
  var ERRORS = {
    AI_PROVIDER_UNAVAILABLE: 'AI_PROVIDER_UNAVAILABLE',
    AI_PROVIDER_TIMEOUT: 'AI_PROVIDER_TIMEOUT',
    AI_INVALID_RESPONSE: 'AI_INVALID_RESPONSE',
    AI_INVALID_ACTION: 'AI_INVALID_ACTION',
    AI_RATE_LIMITED: 'AI_RATE_LIMITED',
    AI_CONTEXT_TOO_LARGE: 'AI_CONTEXT_TOO_LARGE',
    AI_REQUEST_INVALID: 'AI_REQUEST_INVALID',
    AI_CONFIGURATION_ERROR: 'AI_CONFIGURATION_ERROR',
    AI_TOOL_ERROR: 'AI_TOOL_ERROR',
    AI_NETWORK_ERROR: 'AI_NETWORK_ERROR',
    AI_UNAUTHORIZED_ACTION: 'AI_UNAUTHORIZED_ACTION'
  };

  // ── Allowlists (the ONLY intents/actions the model may emit) ─────────────────
  // Read-only / prepare-only. There is no EXECUTE in Phase 8. Any intent or
  // action not listed here is rejected (see validateNemotronResponse).
  var ALLOWED_INTENTS = [
    'AUDIT_CONTRACT',
    'CREATE_CONTRACT',
    'INSPECT_CONTRACT',
    'INTERACT_CONTRACT',
    'VIEW_PORTFOLIO',
    'CHECK_APPROVALS',
    'ASSESS_APPROVAL',
    'EXPLAIN_FINDINGS',
    'EXPLAIN_FINDING',
    'GET_AUDIT_HISTORY',
    'GET_LAST_AUDIT',
    'GET_TRANSACTION',
    'GET_TRANSACTION_STATUS',
    'GET_BALANCE',
    'GET_NETWORK',
    'GET_DEPLOYMENT',
    'GET_PORTFOLIO',
    'SEND'
  ];

  var ALLOWED_ACTIONS = [
    'OPEN_CONTRACT_STUDIO',
    'PREPARE_SEND'
  ];

  // Explicitly dangerous intents/actions that must never run.
  var FORBIDDEN = [
    'EXECUTE_ARBITRARY_RPC', 'RUN_JAVASCRIPT', 'CALL_ARBITRARY_FUNCTION',
    'TRANSFER_ALL_FUNDS', 'DRAIN_WALLET', 'EXECUTE', 'SIGN_TRANSACTION',
    'SUBMIT_TRANSACTION', 'SEND_TRANSACTION'
  ];

  var LIMITS = {
    MAX_CHAT_MESSAGES: 20,
    MAX_MESSAGE_CHARS: 4000,
    MAX_CONTEXT_CHARS: 12000,
    MAX_TOOL_RESULT_CHARS: 4000
  };

  function allowlistIndex(name) {
    return ALLOWED_INTENTS.indexOf(name) !== -1;
  }

  // ── Normalization: turn whatever the model returned into a parsed object ────
  // Handles plain JSON, markdown-fenced JSON, JSON wrapped in prose, and
  // already-parsed objects. Never throws.

  function stripMarkdownFences(text) {
    return String(text || '')
      .replace(/^\s*```[a-zA-Z0-9_-]*\s*\n?/, '')
      .replace(/\n?\s*```\s*$/, '')
      .trim();
  }

  function removeTrailingCommas(text) {
    return String(text).replace(/,(\s*[}\]])/g, '$1');
  }

  function extractJsonObject(text) {
    var t = String(text || '');
    var start = t.indexOf('{');
    var end = t.lastIndexOf('}');
    if (start === -1 || end === -1 || end <= start) return null;
    return t.slice(start, end + 1);
  }

  function normalizeNemotronResponse(raw) {
    if (raw === null || raw === undefined) {
      return { ok: false, error: ERRORS.AI_INVALID_RESPONSE, detail: 'null/undefined' };
    }
    if (typeof raw === 'object' && !Array.isArray(raw)) {
      return { ok: true, value: raw };
    }
    if (typeof raw === 'string') {
      var text = raw.trim();
      if (!text) return { ok: false, error: ERRORS.AI_INVALID_RESPONSE, detail: 'empty' };
      var cleaned = removeTrailingCommas(stripMarkdownFences(text));
      try { return { ok: true, value: JSON.parse(cleaned) }; } catch (e1) { /* fall through */ }
      var extracted = extractJsonObject(cleaned);
      if (extracted !== null) {
        try { return { ok: true, value: JSON.parse(removeTrailingCommas(extracted)) }; } catch (e2) { /* fall through */ }
      }
      // No JSON at all → treat as a plain prose message (no intent/action).
      return { ok: true, value: { message: text, intent: null, action: null } };
    }
    return { ok: false, error: ERRORS.AI_INVALID_RESPONSE, detail: 'unexpected type ' + typeof raw };
  }

  // ── Validation: enforce the allowlist and shape, strip unknown fields ───────

  function validateNemotronResponse(obj) {
    var errors = [];
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      return { valid: false, errors: ['response is not an object'], normalized: { message: '', intent: null, action: null } };
    }

    var message = typeof obj.message === 'string' ? obj.message : '';
    var intent = null;
    var action = null;

    if (obj.intent !== undefined && obj.intent !== null) {
      if (typeof obj.intent !== 'object' || Array.isArray(obj.intent)) {
        errors.push('intent must be an object or null');
      } else {
        var name = (typeof obj.intent.name === 'string') ? obj.intent.name.trim().toUpperCase() : '';
        if (!name) {
          errors.push('intent.name is required when intent is present');
        } else if (FORBIDDEN.indexOf(name) !== -1) {
          errors.push('forbidden intent: ' + name);
        } else if (!allowlistIndex(name)) {
          errors.push('unknown intent: ' + name);
        } else {
          var confidence = (typeof obj.intent.confidence === 'number')
            ? Math.max(0, Math.min(1, obj.intent.confidence))
            : null;
          var parameters = (obj.intent.parameters && typeof obj.intent.parameters === 'object' && !Array.isArray(obj.intent.parameters))
            ? obj.intent.parameters : {};
          var missing = Array.isArray(obj.intent.missingParameters)
            ? obj.intent.missingParameters.filter(function (p) { return typeof p === 'string'; }).slice(0, 16)
            : [];
          intent = {
            name: name,
            confidence: confidence,
            parameters: sanitizeParameters(parameters),
            missingParameters: missing
          };
        }
      }
    }

    if (obj.action !== undefined && obj.action !== null) {
      if (typeof obj.action !== 'object' || Array.isArray(obj.action)) {
        errors.push('action must be an object or null');
      } else {
        var type = (typeof obj.action.type === 'string') ? obj.action.type.trim().toUpperCase() : '';
        if (!type) {
          errors.push('action.type is required when action is present');
        } else if (FORBIDDEN.indexOf(type) !== -1) {
          errors.push('forbidden action: ' + type);
        } else if (ALLOWED_ACTIONS.indexOf(type) === -1) {
          errors.push('unknown action type: ' + type);
        } else {
          action = { type: type, requiresConfirmation: obj.action.requiresConfirmation !== false };
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors: errors,
      normalized: { message: message, intent: intent, action: action }
    };
  }

  // Coerce parameter values to a safe primitive-only subset (no nested objects
  // with functions, no prototype tricks, bounded depth).
  function sanitizeParameters(params) {
    var out = {};
    var count = 0;
    for (var k in params) {
      if (count >= 32) break;
      if (!Object.prototype.hasOwnProperty.call(params, k)) continue;
      var v = params[k];
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
        out[k] = (typeof v === 'string') ? v.slice(0, 200) : v;
        count++;
      }
    }
    return out;
  }

  // ── Context + message building (deterministic limits) ───────────────────────

  function sanitizeContext(context) {
    var c = context || {};
    // Only safe, whitelisted summary fields may leave the browser. No secrets,
    // no private keys, no raw browser-storage dumps.
    return {
      app: { name: 'forgeContract' },
      network: {
        audit: pickNetwork(c.network && c.network.audit),
        transaction: pickNetwork(c.network && c.network.transaction)
      },
      wallet: {
        connected: !!((c.wallet && c.wallet.connected)),
        address: (c.wallet && typeof c.wallet.address === 'string') ? c.wallet.address.slice(0, 64) : null,
        chainId: (c.wallet && c.wallet.chainId != null) ? c.wallet.chainId : null
      },
      activeChat: {
        sessionId: (c.activeChat && typeof c.activeChat.sessionId === 'string') ? c.activeChat.sessionId.slice(0, 128) : null
      },
      lastAudit: (c.lastAudit && c.lastAudit.available) ? {
        available: true,
        address: (typeof c.lastAudit.address === 'string') ? c.lastAudit.address.slice(0, 64) : null,
        score: (typeof c.lastAudit.score === 'number') ? c.lastAudit.score : null,
        verdict: (typeof c.lastAudit.verdict === 'string') ? c.lastAudit.verdict.slice(0, 32) : null,
        findingCount: (typeof c.lastAudit.findingCount === 'number') ? c.lastAudit.findingCount : null
      } : { available: false },
      lastDeployment: (c.lastDeployment && c.lastDeployment.available) ? {
        available: true,
        address: (typeof c.lastDeployment.address === 'string') ? c.lastDeployment.address.slice(0, 64) : null,
        networkId: (typeof c.lastDeployment.networkId === 'string') ? c.lastDeployment.networkId.slice(0, 64) : null
      } : { available: false },
      pendingTransactionCount: (typeof c.pendingTransactionCount === 'number') ? c.pendingTransactionCount : 0
    };
  }

  function pickNetwork(n) {
    if (!n || typeof n !== 'object') return null;
    return {
      id: (n.id != null) ? n.id : null,
      name: (typeof n.name === 'string') ? n.name.slice(0, 64) : null
    };
  }

  // Build the request messages: a system context block + recent history + the
  // current user message. Never exceeds the configured limits.
  function buildMessages(text, context, history) {
    var msgs = [];
    var ctx = sanitizeContext(context);
    msgs.push({ role: 'system', content: 'forgeContract context: ' + JSON.stringify(ctx) });

    var hist = Array.isArray(history) ? history : [];
    var budget = LIMITS.MAX_CHAT_MESSAGES - 2;
    var recent = hist.slice(-budget);
    var total = 0;
    var out = [];
    for (var i = 0; i < recent.length; i++) {
      var m = recent[i];
      if (!m || (m.role !== 'user' && m.role !== 'assistant')) continue;
      var content = (typeof m.content === 'string') ? m.content.slice(0, LIMITS.MAX_MESSAGE_CHARS) : '';
      total += content.length;
      if (total > LIMITS.MAX_CONTEXT_CHARS) break;
      out.push({ role: m.role, content: content });
    }
    for (var j = 0; j < out.length; j++) msgs.push(out[j]);

    msgs.push({ role: 'user', content: String(text || '').slice(0, LIMITS.MAX_MESSAGE_CHARS) });
    return msgs;
  }

  // ── Network call (injectable for tests) ─────────────────────────────────────

  function requestChat(messages, opts) {
    opts = opts || {};
    var fetchFn = opts.fetch || (typeof fetch === 'function' ? fetch : (typeof globalThis !== 'undefined' && globalThis.fetch ? globalThis.fetch : null));
    if (!fetchFn) return Promise.reject(new Error(ERRORS.AI_NETWORK_ERROR));
    var endpoint = opts.endpoint || ENDPOINT;
    var controller;
    var timeout = (opts.timeoutMs !== undefined) ? opts.timeoutMs : 30000;
    var timer;
    if (typeof AbortController !== 'undefined') {
      controller = new AbortController();
      timer = setTimeout(function () { try { controller.abort(); } catch (e) {} }, timeout);
    }
    var init = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: messages })
    };
    if (controller) init.signal = controller.signal;

    return Promise.resolve()
      .then(function () { return fetchFn(endpoint, init); })
      .then(function (res) {
        return res.json().catch(function () { return null; }).then(function (data) {
          return { status: res.status, data: data };
        });
      })
      .then(function (r) {
        if (!r.data) throw new Error(ERRORS.AI_PROVIDER_UNAVAILABLE);
        if (!(r.status >= 200 && r.status < 300)) {
          var code = (r.data.error && r.data.error.code) || mapStatus(r.status);
          var err = new Error(code);
          err.code = code;
          throw err;
        }
        return r.data.content;
      })
      .catch(function (e) {
        if (e && (e.name === 'AbortError')) { e = new Error(ERRORS.AI_PROVIDER_TIMEOUT); e.code = ERRORS.AI_PROVIDER_TIMEOUT; }
        if (!e.code) { e = e || new Error(ERRORS.AI_NETWORK_ERROR); e.code = e.code || ERRORS.AI_NETWORK_ERROR; }
        throw e;
      })
      .finally(function () { if (timer) clearTimeout(timer); });
  }

  function mapStatus(status) {
    if (status === 429) return ERRORS.AI_RATE_LIMITED;
    if (status === 504) return ERRORS.AI_PROVIDER_TIMEOUT;
    if (status === 413) return ERRORS.AI_CONTEXT_TOO_LARGE;
    if (status === 500) return ERRORS.AI_CONFIGURATION_ERROR;
    if (status === 400) return ERRORS.AI_REQUEST_INVALID;
    return ERRORS.AI_PROVIDER_UNAVAILABLE;
  }

  // Full pipeline: request → normalize → validate. Returns { ok, message,
  // intent, action, error } — never throws.
  async function chat(text, context, history, opts) {
    var messages = buildMessages(text, context, history);
    try {
      var content = await requestChat(messages, opts);
      var norm = normalizeNemotronResponse(content);
      if (!norm.ok) {
        return { ok: false, error: norm.error, message: '', intent: null, action: null };
      }
      var val = validateNemotronResponse(norm.value);
      if (!val.valid) {
        return { ok: false, error: ERRORS.AI_INVALID_RESPONSE, message: norm.value.message || '', intent: null, action: null, validationErrors: val.errors };
      }
      return { ok: true, error: null, message: val.normalized.message, intent: val.normalized.intent, action: val.normalized.action };
    } catch (e) {
      return { ok: false, error: (e && e.code) || ERRORS.AI_NETWORK_ERROR, message: '', intent: null, action: null };
    }
  }

  return {
    ENDPOINT: ENDPOINT,
    ERRORS: ERRORS,
    ALLOWED_INTENTS: ALLOWED_INTENTS,
    ALLOWED_ACTIONS: ALLOWED_ACTIONS,
    FORBIDDEN: FORBIDDEN,
    LIMITS: LIMITS,
    normalizeNemotronResponse: normalizeNemotronResponse,
    validateNemotronResponse: validateNemotronResponse,
    sanitizeContext: sanitizeContext,
    buildMessages: buildMessages,
    requestChat: requestChat,
    chat: chat
  };
});
