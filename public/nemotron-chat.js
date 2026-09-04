// ═══════════════════════════════════════════════════════════════════════════════
// forgeContract — Nemotron chat orchestrator (Phase 8)
//
// Bridges the Nemotron client to the existing Chat + Intent Router + read-only
// tools. It does NOT create a second Intent Router, does NOT control the wallet,
// and never executes blockchain actions. It returns a plain result object; the
// caller (index.html) renders it session-safely.
//
// Source-of-truth hierarchy (enforced here):
//   1. on-chain GenLayer state
//   2. real RPC/network state
//   3. deterministic forgeContract engines
//   4. persisted ChatStore state
//   5. Nemotron interpretation
//
// Pure (no DOM), testable in Node with an injected state provider.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAINemotronChat = api;
})(function () {
  'use strict';

  function client() {
    return (typeof globalThis !== 'undefined' ? globalThis : window).AuditAINemotronClient || null;
  }

  // ── Tool registry ───────────────────────────────────────────────────────────
  // Explicit allowlist. No arbitrary function names from the model are ever
  // looked up dynamically by untrusted input — every tool is registered here.
  var _tools = {};

  function registerTool(name, fn) {
    if (typeof name !== 'string' || typeof fn !== 'function') return false;
    _tools[name] = fn;
    return true;
  }
  function unregisterTool(name) { delete _tools[name]; }
  function listTools() { return Object.keys(_tools).slice(); }
  function hasTool(name) { return Object.prototype.hasOwnProperty.call(_tools, name); }

  // Intent name → registered tool name. Only these intents may invoke a tool.
  var INTENT_TOOL = {
    GET_WALLET: 'get_wallet',
    GET_NETWORK: 'get_network',
    GET_LAST_AUDIT: 'get_last_audit',
    EXPLAIN_FINDING: 'get_last_audit',
    EXPLAIN_FINDINGS: 'get_last_audit',
    GET_AUDIT_HISTORY: 'get_audit_history',
    GET_TRANSACTION: 'get_transaction',
    GET_TRANSACTION_STATUS: 'get_transaction_status',
    GET_DEPLOYMENT: 'get_deployment',
    GET_PORTFOLIO: 'get_portfolio',
    GET_BALANCE: 'get_balance',
    VIEW_PORTFOLIO: 'get_portfolio'
  };

  // Intents that map straight onto the existing deterministic Intent Router.
  var ROUTER_INTENTS = {
    AUDIT_CONTRACT: 'AUDIT_CONTRACT',
    CREATE_CONTRACT: 'CREATE_CONTRACT',
    INSPECT_CONTRACT: 'INSPECT_CONTRACT',
    INTERACT_CONTRACT: 'INTERACT_CONTRACT',
    CHECK_APPROVALS: 'CHECK_APPROVALS',
    ASSESS_APPROVAL: 'ASSESS_APPROVAL'
  };

  function getState(opts) {
    return (opts && opts.state) || {};
  }

  function avail(text) { return { ok: true, text: text, unavailable: false }; }
  function unavailable(text) { return { ok: false, text: text, unavailable: true }; }

  // ── Read-only tools (real data only — never fabricated) ─────────────────────

  function toolGetWallet(params, state) {
    var fn = state.getWallet;
    if (typeof fn !== 'function') return unavailable('No wallet data available.');
    var w = fn();
    if (!w || !w.address) return unavailable('No wallet is connected.');
    return avail('Connected wallet: `' + w.address + '`' + (w.chainId != null ? ' on chain `' + w.chainId + '`' : '') + '.');
  }

  function toolGetNetwork(params, state) {
    var fn = state.getNetwork;
    if (typeof fn === 'function') {
      var n = fn();
      if (n && (n.id != null || n.name)) {
        return avail('Current network: **' + (n.name || 'Unknown') + '**' + (n.id != null ? ' (chain id `' + n.id + '`)' : '') + '.');
      }
    }
    return unavailable('Network information is unavailable.');
  }

  function toolGetLastAudit(params, state) {
    var fn = state.getLastAudit;
    if (typeof fn !== 'function') return unavailable('No audit data available.');
    var a = fn();
    if (!a) return unavailable('There is no recent audit yet. Audit a contract first.');
    var lines = [];
    lines.push('Last audit of `' + (a.address || '').slice(0, 12) + '…`');
    if (typeof a.score === 'number') lines.push('Score: **' + a.score + '**');
    if (a.verdict) lines.push('Verdict: **' + a.verdict + '**');
    var findings = Array.isArray(a.findings) ? a.findings : [];
    lines.push('Findings: **' + findings.length + '**');
    findings.slice(0, 6).forEach(function (f) {
      lines.push('• ' + (f.title || f.id || 'finding') + ' (' + (f.severity || 'INFO') + ', ' + (f.confidence || 'LOW') + ')');
    });
    lines.push('*Capability ≠ Vulnerability · UNKNOWN ≠ Vulnerable*');
    return avail(lines.join('\n'));
  }

  function toolGetAuditHistory(params, state) {
    var fn = state.getHistory;
    if (typeof fn !== 'function') return unavailable('Audit history is unavailable.');
    var h = fn();
    if (!Array.isArray(h) || h.length === 0) return unavailable('No audit history yet.');
    var lines = ['Recent audits:'];
    h.slice(0, 10).forEach(function (item) {
      var addr = (item && item.address) ? String(item.address).slice(0, 12) + '…' : '?';
      var score = (item && typeof item.score === 'number') ? item.score : '—';
      var verdict = (item && item.verdict) ? item.verdict : '';
      lines.push('• `' + addr + '` — score ' + score + (verdict ? ' (' + verdict + ')' : ''));
    });
    return avail(lines.join('\n'));
  }

  function toolGetTransaction(params, state) {
    var fn = state.loadTxs;
    if (typeof fn !== 'function') return unavailable('Transaction data is unavailable.');
    var txs = fn();
    if (!Array.isArray(txs) || txs.length === 0) return unavailable('No transactions recorded.');
    var hash = (params && params.txHash) || null;
    if (hash) {
      var match = txs.find(function (t) { return t && String(t.txHash) === String(hash); });
      if (!match) return unavailable('No transaction found with hash `' + hash + '`.');
      txs = [match];
    }
    var lines = ['Transactions:'];
    txs.slice(0, 8).forEach(function (t) {
      lines.push('• `' + String(t.txHash).slice(0, 14) + '…` — ' + (t.status || 'UNKNOWN') + (t.operation ? ' (' + t.operation + ')' : ''));
    });
    return avail(lines.join('\n'));
  }

  function toolGetTransactionStatus(params, state) {
    var hash = (params && params.txHash) || null;
    var fn = state.getTxState;
    if (typeof fn === 'function' && hash) {
      var s = fn(hash);
      if (s && s.status) {
        return avail('Transaction `' + String(hash).slice(0, 14) + '…` status: **' + s.status + '**.');
      }
    }
    return unavailable('Live transaction status is unavailable for that hash.');
  }

  function toolGetDeployment(params, state) {
    var fn = state.getDeployment;
    if (typeof fn !== 'function') return unavailable('Deployment data is unavailable.');
    var d = fn();
    if (!d || !d.address) return unavailable('No deployment recorded yet.');
    return avail('Last deployment: `' + d.address + '`' + (d.txHash ? ' (tx `' + String(d.txHash).slice(0, 14) + '…`)' : '') + '.');
  }

  function toolGetPortfolio(params, state) {
    var fn = state.getPortfolio;
    if (typeof fn !== 'function') return unavailable('Portfolio data is unavailable.');
    var p = fn();
    if (!p) return unavailable('No portfolio scan recorded yet.');
    if (Array.isArray(p.items) && p.items.length) {
      var lines = ['Portfolio:'];
      p.items.slice(0, 10).forEach(function (it) {
        lines.push('• ' + (it.name || it.address || 'token'));
      });
      return avail(lines.join('\n'));
    }
    return avail('Portfolio data is present but empty.');
  }

  async function toolGetBalance(params, state) {
    var fn = state.getBalance;
    if (typeof fn !== 'function') return unavailable('Balance lookup is unavailable.');
    try {
      var b = await fn();
      if (!b || typeof b.balance !== 'string') return unavailable('Balance is unavailable.');
      return avail('Balance: **' + b.formatted + '** ' + (b.symbol || '') + '.');
    } catch (e) {
      return unavailable('Balance is unavailable.');
    }
  }

  // ── Tool execution (allowlisted; never arbitrary) ───────────────────────────

  async function runTool(name, params, opts) {
    if (!hasTool(name)) {
      return { ok: false, error: 'AI_TOOL_ERROR', text: 'Tool unavailable.', data: null };
    }
    var state = getState(opts);
    try {
      var fn = _tools[name];
      var res = await fn(params || {}, state, opts || {});
      if (res && res.unavailable) {
        return { ok: false, error: null, text: res.text, data: null, unavailable: true };
      }
      return { ok: true, error: null, text: res && res.text ? res.text : '', data: res && res.data ? res.data : null };
    } catch (e) {
      return { ok: false, error: 'AI_TOOL_ERROR', text: 'Tool unavailable.', data: null };
    }
  }

  function prepareSendMessage(intent) {
    var p = (intent && intent.parameters) || {};
    var token = p.token || p.asset || 'the asset';
    var amount = p.amount != null ? p.amount : 'the amount';
    var recipient = p.recipient || p.to || 'the recipient';
    return 'I can prepare that transfer: **' + amount + ' ' + token + '** to `' + recipient + '`.\n\n⚠️ This action requires explicit confirmation and has NOT been executed. forgeContract\u2019s deterministic transaction engine (with the GenLayer lifecycle) handles signing and submission only after you approve it.';
  }

  // ── Orchestration ───────────────────────────────────────────────────────────

  // text: the user message. ctx: the (already sanitized) app context sent to the
  // model. history: recent {role,content} turns. opts: { sessionId, state, ... }.
  // Returns a plain result (never throws). The caller renders session-safely.
  async function handleMessage(text, ctx, history, opts) {
    opts = opts || {};
    var c = client();
    if (!c || typeof c.chat !== 'function') {
      return { ok: false, fallback: true, error: 'AI_CONFIGURATION_ERROR', message: '', intent: null, action: null, source: 'deterministic' };
    }

    var res;
    try {
      res = await c.chat(text, ctx, history, opts);
    } catch (e) {
      res = { ok: false, error: (e && e.code) || 'AI_NETWORK_ERROR' };
    }

    if (!res.ok) {
      return {
        ok: false, fallback: true, error: res.error,
        message: 'AI assistance is temporarily unavailable. I can still use the available deterministic tools.',
        intent: null, action: null, source: 'deterministic'
      };
    }

    var intent = res.intent;
    var action = res.action;

    // No structured intent → plain conversational answer.
    if (!intent) {
      return { ok: true, fallback: false, error: null, message: res.message, intent: null, action: action, source: 'nemotron' };
    }

    // SEND → PREPARE only. Never executed.
    if (intent.name === 'SEND') {
      var base = (res.message && res.message.trim()) ? res.message.trim() : null;
      var note = '⚠️ This action requires explicit confirmation and has NOT been executed. forgeContract\u2019s deterministic transaction engine (with the GenLayer lifecycle) handles signing and submission only after you approve it.';
      var sendMsg = base ? (base + '\n\n' + note) : prepareSendMessage(intent);
      return {
        ok: true, fallback: false, error: null,
        message: sendMsg,
        intent: intent,
        action: action || { type: 'PREPARE_SEND', requiresConfirmation: true },
        tool: null, source: 'nemotron'
      };
    }

    // Router intents → hand back to the deterministic engine.
    if (ROUTER_INTENTS[intent.name]) {
      return {
        ok: true, fallback: false, error: null,
        message: res.message, intent: intent, action: action,
        reroute: ROUTER_INTENTS[intent.name], tool: null, source: 'nemotron'
      };
    }

    // Read-only tool intents → run the allowlisted tool against real state.
    var toolName = INTENT_TOOL[intent.name];
    if (toolName) {
      var tr = await runTool(toolName, intent.parameters, opts);
      var combined = compose(res.message, tr.text, intent.name);
      return {
        ok: true, fallback: false, error: tr.error,
        message: combined, intent: intent, action: action,
        tool: { name: toolName, data: tr.data },
        source: 'nemotron'
      };
    }

    // Intent known but not actionable here → fall back to the model's message.
    return { ok: true, fallback: false, error: null, message: res.message, intent: intent, action: action, tool: null, source: 'nemotron' };
  }

  function compose(aiText, toolText, intentName) {
    var parts = [];
    if (aiText && aiText.trim()) parts.push(aiText.trim());
    if (toolText && toolText.trim()) parts.push(toolText.trim());
    return parts.join('\n\n');
  }

  // ── Register the default read-only tools ────────────────────────────────────
  registerTool('get_wallet', toolGetWallet);
  registerTool('get_network', toolGetNetwork);
  registerTool('get_last_audit', toolGetLastAudit);
  registerTool('get_audit_history', toolGetAuditHistory);
  registerTool('get_transaction', toolGetTransaction);
  registerTool('get_transaction_status', toolGetTransactionStatus);
  registerTool('get_deployment', toolGetDeployment);
  registerTool('get_portfolio', toolGetPortfolio);
  registerTool('get_balance', toolGetBalance);

  return {
    INTENT_TOOL: INTENT_TOOL,
    ROUTER_INTENTS: ROUTER_INTENTS,
    registerTool: registerTool,
    unregisterTool: unregisterTool,
    listTools: listTools,
    hasTool: hasTool,
    runTool: runTool,
    handleMessage: handleMessage,
    prepareSendMessage: prepareSendMessage,
    compose: compose
  };
});
