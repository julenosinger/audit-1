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

  var PUBLISHED_KEY = 'auditai.genlayer.published';
  var NETWORK_KEY = 'auditai.genlayer.network';
  var DEFAULT_NETWORK_ID = 'studionet';

  // ── GenLayer networks (single source of truth in genlayer-client.js) ───────
  // Network + contract pairing lives in the adapter (window.AuditAIGenLayerClient.NETWORKS).
  // The UI reads the selected network and its paired contract from there.
  function networks() {
    return (window.AuditAIGenLayerClient && window.AuditAIGenLayerClient.NETWORKS) || {};
  }

  function getNetworkId() {
    var n = '';
    try { n = localStorage.getItem(NETWORK_KEY) || ''; } catch (e) { n = ''; }
    var all = networks();
    if (all[n]) return n;
    return DEFAULT_NETWORK_ID;
  }

  function setNetworkId(id) {
    if (!networks()[id]) return;
    try { localStorage.setItem(NETWORK_KEY, String(id)); } catch (e) {}
    _client = null;          // invalidate cached adapter (network changed)
    _clientNetwork = null;
  }

  function getNetwork() {
    return networks()[getNetworkId()] || null;
  }

  function getContract() {
    var net = getNetwork();
    return net ? net.contract : '';
  }

  function setContract(addr) {
    // Legacy dev escape hatch (unused by the network-aware path).
    try { localStorage.setItem('auditai.genlayer.contract', String(addr || '').trim()); } catch (e) {}
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
  var _clientNetwork = null;

  function loadClient() {
    if (_client) return Promise.resolve(_client);
    if (window.genlayer) { _client = window.genlayer; return Promise.resolve(_client); }
    // No confirmed CDN yet. Return a rejected promise so callers use the
    // Studio fallback instead of crashing.
    return Promise.reject(new Error('genlayer-js not available'));
  }

  // Synchronous accessor for the GenLayer client adapter (null if not wired).
  // Creates the bundled adapter (public/genlayer-client.js) bound to the
  // currently selected network, and caches it by network id so switching
  // networks recreates a correctly-paired adapter.
  function getClient() {
    var netId = getNetworkId();
    if (_client && _clientNetwork === netId) return _client;
    var adapterFactory = window.AuditAIGenLayerClient;
    if (adapterFactory && typeof adapterFactory.createAdapter === 'function') {
      try { _client = adapterFactory.createAdapter(null, { networkId: netId }); } catch (e) { _client = null; }
      if (_client) { _clientNetwork = netId; return _client; }
    }
    if (window.genlayer) { _client = window.genlayer; _clientNetwork = netId; return _client; }
    _clientNetwork = netId;
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
    PUBLISHED_KEY: PUBLISHED_KEY,
    NETWORK_KEY: NETWORK_KEY,
    DEFAULT_NETWORK_ID: DEFAULT_NETWORK_ID,
    NETWORKS: networks(),
    getNetworkId: getNetworkId,
    setNetworkId: setNetworkId,
    getNetwork: getNetwork,
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
