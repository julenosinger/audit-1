// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer bridge
//
// Thin client-side helper to publish an EVM audit result into the AuditAI
// Intelligent Contract (contracts/audit_ai.py) deployed on GenLayer.
//
// It is intentionally defensive: it never throws, never depends on a hard CDN
// that could break the ethers.js flow, and falls back to Studio instructions
// (copy the method call) when `genlayer-js` is not available.
// ═══════════════════════════════════════════════════════════════════════════════
(function () {
  'use strict';

  var STORAGE_KEY = 'auditai.genlayer.contract';
  var PUBLISHED_KEY = 'auditai.genlayer.published';

  // ── Production contract configuration (single authoritative source) ────────
  // The real AuditAI Intelligent Contract address on Bradbury. Empty means the
  // contract is not deployed yet (GENLAYER_AUDITOR_NOT_DEPLOYED). The UI keeps a
  // localStorage override (STORAGE_KEY) as an advanced/debug escape hatch only.
  var DEFAULT_CONTRACT_ADDRESS = '';

  // ── GenLayer networks ──────────────────────────────────────────────────────
  // chainId + RPC from the official Networks docs:
  //   https://docs.genlayer.com/developers/networks
  var NETWORKS = {
    studionet: { name: 'Studionet', chainId: 61999, rpc: 'https://studio.genlayer.com/api' },
    bradbury:  { name: 'Bradbury',  chainId: 4221,  rpc: 'https://rpc-bradbury.genlayer.com' }
  };

  function getContract() {
    var stored = '';
    try { stored = localStorage.getItem(STORAGE_KEY) || ''; } catch (e) { stored = ''; }
    return stored || DEFAULT_CONTRACT_ADDRESS;
  }

  function setContract(addr) {
    try { localStorage.setItem(STORAGE_KEY, String(addr || '').trim()); } catch (e) {}
  }

  function short(addr) {
    if (!addr) return 'not set';
    return addr.slice(0, 10) + '\u2026' + addr.slice(-6);
  }

  function isSet(addr) {
    return !!(addr && /^0x[0-9a-fA-F]{40}$/.test(addr));
  }

  function getPublished() {
    try { return JSON.parse(localStorage.getItem(PUBLISHED_KEY) || '{}'); } catch (e) { return {}; }
  }

  function markPublished(contractAddr) {
    try {
      var p = getPublished();
      p[String(contractAddr).toLowerCase()] = Date.now();
      localStorage.setItem(PUBLISHED_KEY, JSON.stringify(p));
    } catch (e) {}
  }

  function isPublished(contractAddr) {
    return !!getPublished()[String(contractAddr).toLowerCase()];
  }

  // ── genlayer-js (optional) ─────────────────────────────────────────────────
  // TODO: if/when genlayer-js is available via a confirmed CDN/bundle, load it
  // here and implement the real write/view calls below.
  //   npm: genlayer-js   →  import { GenLayerClient } from 'genlayer-js'
  var _client = null;

  function loadClient() {
    if (_client) return Promise.resolve(_client);
    if (window.genlayer) { _client = window.genlayer; return Promise.resolve(_client); }
    // No confirmed CDN yet. Return a rejected promise so callers use the
    // Studio fallback instead of crashing.
    return Promise.reject(new Error('genlayer-js not available'));
  }

  // Synchronous accessor for the GenLayer client adapter (null if not wired).
  // Prefers the bundled adapter (public/genlayer-client.js → genlayer-sdk.bundle.js),
  // which implements analyzeEvidence(payload, opts). Falls back to a manually
  // injected window.genlayer for legacy/Studio testing.
  function getClient() {
    if (_client) return _client;
    var adapterFactory = window.AuditAIGenLayerClient;
    if (adapterFactory && typeof adapterFactory.createAdapter === 'function') {
      try { _client = adapterFactory.createAdapter(); } catch (e) { _client = null; }
      if (_client) return _client;
    }
    if (window.genlayer) { _client = window.genlayer; return _client; }
    return null;
  }

  // ── public API ─────────────────────────────────────────────────────────────
  // publish(contractAddr, score, verdict, summary) -> Promise<{ok, message, calldata?}>
  function publish(contractAddr, score, verdict, summary) {
    var target = getContract();
    if (!isSet(target)) {
      return Promise.resolve({
        ok: false,
        needContract: true,
        message: 'No GenLayer contract set. Click "Set GenLayer contract address" in the top bar first.'
      });
    }

    return loadClient().then(function (client) {
      // TODO: real write once the client is wired:
      //   return client.write(target, 'publish_audit', [contractAddr, String(score), verdict, summary]);
      throw new Error('genlayer-js publish not wired yet');
    }).catch(function () {
      return Promise.resolve({
        ok: false,
        fallback: true,
        contract: target,
        message: 'Open GenLayer Studio and call publish_audit on ' + short(target),
        calldata: 'publish_audit(\n  "' + contractAddr + '",\n  "' + score + '",\n  "' + verdict + '",\n  "' + String(summary).replace(/"/g, '\\"') + '"\n)'
      });
    });
  }

  // getOnChain(contractAddr) -> Promise<string|null>  (format "{score}|{verdict}|{summary}")
  function getOnChain(contractAddr) {
    var target = getContract();
    if (!isSet(target)) return Promise.resolve(null);

    return loadClient().then(function (client) {
      // TODO: real view once wired:
      //   return client.view(target, 'get_audit', [contractAddr]);
      return null;
    }).catch(function () { return null; });
  }

  // analyzeAndPublish(contractAddr, context) -> Promise<{ok, fallback, calldata, message}>
  // Calls the GenLayer-native LLM method analyze_and_publish. Falls back to
  // Studio instructions (copy calldata) when genlayer-js is not wired.
  function analyzeAndPublish(contractAddr, context) {
    var target = getContract();
    if (!isSet(target)) {
      return Promise.resolve({
        ok: false,
        needContract: true,
        message: 'No GenLayer contract set. Click the top-bar pill first.'
      });
    }

    return loadClient().then(function (client) {
      // TODO: real write once genlayer-js client is wired:
      //   return client.write(target, 'analyze_and_publish', [contractAddr, String(context).slice(0, 8000)]);
      throw new Error('genlayer-js analyze not wired yet');
    }).catch(function () {
      var snippet = String(context || '').slice(0, 8000)
        .replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
      return Promise.resolve({
        ok: false,
        fallback: true,
        contract: target,
        message: 'Open GenLayer Studio and call analyze_and_publish on ' + short(target),
        calldata: 'analyze_and_publish(\n  "' + contractAddr + '",\n  "' + snippet + '"\n)'
      });
    });
  }

  // getAudit(contractAddr) -> Promise<string|null>  (alias of getOnChain)
  function getAudit(contractAddr) {
    return getOnChain(contractAddr);
  }

  function copyToClipboard(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) {}
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (e) { return false; }
  }

  window.AuditAIGenLayer = {
    STORAGE_KEY: STORAGE_KEY,
    PUBLISHED_KEY: PUBLISHED_KEY,
    NETWORKS: NETWORKS,
    DEFAULT_CONTRACT_ADDRESS: DEFAULT_CONTRACT_ADDRESS,
    getContract: getContract,
    setContract: setContract,
    short: short,
    isSet: isSet,
    isPublished: isPublished,
    markPublished: markPublished,
    publish: publish,
    getOnChain: getOnChain,
    analyzeAndPublish: analyzeAndPublish,
    getAudit: getAudit,
    getClient: getClient,
    copyToClipboard: copyToClipboard
  };
})();
