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
  var DEFAULT_NETWORK_ID = 'bradbury';

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

  // ── genlayer-js (bundled) ──────────────────────────────────────────────────
  // The real client is the adapter in public/genlayer-client.js (wired to the
  // official genlayer-js SDK bundled into public/genlayer-sdk.bundle.js).
  var _client = null;
  var _clientNetwork = null;

  // Synchronous accessor for the GenLayer client adapter (null if not wired).
  // Creates the bundled adapter bound to the currently selected network, and
  // caches it by network id so switching networks recreates a correctly-paired
  // adapter.
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
  // Each write submits the correct method via the bundled genlayer-js client,
  // waits for FINALIZED, reads the contract state, and only then reports it as
  // on-chain. Without a wallet/SDK it falls back to a Studio copy-call that is
  // explicitly OFF-CHAIN (never marked on-chain).

  function fallbackResult(target, method, contractAddr, args, message) {
    var lines = [method + '('];
    for (var i = 0; i < args.length; i++) {
      var v = String(args[i] === null || args[i] === undefined ? '' : args[i])
        .replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
      lines.push('  "' + v + '"' + (i < args.length - 1 ? ',' : ''));
    }
    lines.push(')');
    return {
      ok: false,
      fallback: true,
      offChain: true,
      contract: target,
      message: message,
      calldata: lines.join('\n')
    };
  }

  // Poll a submitted transaction until the chain reports FINALIZED (via the
  // single GenLayerTx engine). ACCEPTED is kept only as an intermediate step.
  function waitFinalized(client, hash, opts) {
    opts = opts || {};
    var Tx = window.AuditAIGenLayerTx;
    if (Tx && typeof Tx.monitorTransaction === 'function' && typeof client.getTransaction === 'function') {
      return Tx.monitorTransaction({
        hash: hash,
        getStatus: function (h) { return client.getTransaction(h); },
        onStatus: function (state, detail) { if (typeof opts.onStatus === 'function') opts.onStatus(state, detail); },
        until: 'FINALIZED',
        pollInterval: opts.pollInterval,
        maxConsecutiveRpcErrors: opts.maxConsecutiveRpcErrors
      }).then(function (outcome) {
        if (outcome.kind === 'FAILED_TERMINAL') { throw new Error(outcome.status); }
        if (!outcome.ok) { throw new Error('GENLAYER_NETWORK_UNAVAILABLE'); }
        return outcome;
      });
    }
    // No engine available — degrade to the adapter receipt waiter (best-effort).
    return client.waitForTransactionReceipt(hash, { status: 'FINALIZED' }).then(function (receipt) {
      if (receipt && receipt.status === 'FAILED') throw new Error('TRANSACTION_FAILED');
      return { kind: 'FINALIZED', status: 'FINALIZED', tx: receipt, hash: hash };
    });
  }

  // After FINALIZED: read get_audit + get_author, then run the centralized
  // OnChainStateVerifier. onChain/verified is TRUE only on VERIFIED_ON_CHAIN.
  function verifyOnChain(client, target, contractAddr, action, expected, hash) {
    var net = getNetwork();
    var Verify = window.AuditAIGenLayerVerify;
    var readAudit = Promise.resolve().then(function () { return client.read(target, 'get_audit', [contractAddr]); }).catch(function () { return null; });
    var readAuthor = Promise.resolve().then(function () { return client.read(target, 'get_author', [contractAddr]); }).catch(function () { return null; });
    return Promise.all([readAudit, readAuthor]).then(function (vals) {
      var reads = { getAudit: vals[0], getAuthor: vals[1] };
      var verification;
      if (Verify && typeof Verify.verifyFinalizedOnChainState === 'function') {
        verification = Verify.verifyFinalizedOnChainState({
          action: action,
          txHash: hash,
          contractAddress: contractAddr,
          networkId: net ? net.id : null,
          chainId: net ? net.chainId : null,
          submittedBy: expected.submittedBy || null,
          expected: expected,
          state: reads
        });
      } else {
        var hasData = (typeof reads.getAudit === 'string' && reads.getAudit && reads.getAudit !== 'NO_AUDIT');
        verification = {
          verified: hasData,
          status: hasData ? 'VERIFIED_ON_CHAIN' : 'VERIFICATION_PENDING',
          matchedFields: [],
          mismatchFields: [],
          verifiedAt: hasData ? Date.now() : null
        };
      }
      var explorerUrl = (Verify && typeof Verify.explorerTxUrl === 'function')
        ? Verify.explorerTxUrl(net ? net.id : null, hash)
        : null;
      return {
        ok: true,
        hash: hash,
        verified: verification.verified,
        verificationStatus: verification.status,
        onChain: verification.verified,
        matchedFields: verification.matchedFields || [],
        mismatchFields: verification.mismatchFields || [],
        result: reads.getAudit,
        author: reads.getAuthor,
        contract: target,
        explorerUrl: explorerUrl
      };
    });
  }

  // publish(contractAddr, score, verdict, findings, opts) -> Promise
  //   opts: { account, onStatus, pollInterval, maxConsecutiveRpcErrors }
  //   resolves { ok:true, hash, verified, verificationStatus, onChain, result }
  //   only after FINALIZED + read + state verification.
  function publish(contractAddr, score, verdict, findings, opts) {
    opts = opts || {};
    var target = getContract();
    if (!isSet(target)) {
      return Promise.resolve({ ok: false, needContract: true, message: 'No GenLayer contract set. Click "Set GenLayer contract address" in the top bar first.' });
    }
    var client = getClient();
    var account = opts.account;
    var args = [contractAddr, String(score), String(verdict), findings];
    if (!client || typeof client.writeContract !== 'function' || !account) {
      return Promise.resolve(fallbackResult(target, 'publish_audit', contractAddr, args, 'No wallet connected — the result was NOT published on-chain. Copy the call below and run it in GenLayer Studio on ' + short(target) + '.'));
    }
    var expected = { score: score, verdict: verdict, findings: findings, submittedBy: account };
    return client.writeContract(target, 'publish_audit', args, { account: account })
      .then(function (hash) {
        if (typeof opts.onStatus === 'function') opts.onStatus('SUBMITTED', hash);
        return waitFinalized(client, hash, opts).then(function () {
          return verifyOnChain(client, target, contractAddr, 'publish_audit', expected, hash);
        });
      })
      .catch(function (e) {
        var code = (e && e.message) || 'GENLAYER_ERROR';
        if (code === 'USER_REJECTED') {
          return fallbackResult(target, 'publish_audit', contractAddr, args, 'Signature canceled — the result was NOT published on-chain. Copy the call below and run it in GenLayer Studio on ' + short(target) + '.');
        }
        return { ok: false, error: code, contract: target };
      });
  }

  // getOnChain(contractAddr) -> Promise<string|null>  (format "{score}|{verdict}|{summary}")
  function getOnChain(contractAddr) {
    var target = getContract();
    if (!isSet(target)) return Promise.resolve(null);
    var client = getClient();
    if (!client || typeof client.read !== 'function') return Promise.resolve(null);
    return client.read(target, 'get_audit', [contractAddr])
      .then(function (result) {
        return (typeof result === 'string' && result && result !== 'NO_AUDIT') ? result : null;
      })
      .catch(function () { return null; });
  }

  // analyzeAndPublish(contractAddr, context, opts) -> Promise
  //   Adjudicates via the GenLayer LLM, waits FINALIZED, then reads + verifies
  //   get_audit state before reporting it as on-chain.
  function analyzeAndPublish(contractAddr, context, opts) {
    opts = opts || {};
    var target = getContract();
    if (!isSet(target)) {
      return Promise.resolve({ ok: false, needContract: true, message: 'No GenLayer contract set. Click the top-bar pill first.' });
    }
    var snippet = String(context || '').slice(0, 8000);
    var client = getClient();
    var account = opts.account;
    var args = [contractAddr, snippet];
    if (!client || typeof client.writeContract !== 'function' || !account) {
      return Promise.resolve(fallbackResult(target, 'analyze_and_publish', contractAddr, args, 'No wallet connected — the result was NOT published on-chain. Copy the call below and run it in GenLayer Studio on ' + short(target) + '.'));
    }
    var expected = { submittedBy: account };
    return client.writeContract(target, 'analyze_and_publish', args, { account: account })
      .then(function (hash) {
        if (typeof opts.onStatus === 'function') opts.onStatus('SUBMITTED', hash);
        return waitFinalized(client, hash, opts).then(function () {
          return verifyOnChain(client, target, contractAddr, 'analyze_and_publish', expected, hash);
        });
      })
      .catch(function (e) {
        var code = (e && e.message) || 'GENLAYER_ERROR';
        if (code === 'USER_REJECTED') {
          return fallbackResult(target, 'analyze_and_publish', contractAddr, args, 'Signature canceled — the result was NOT published on-chain. Copy the call below and run it in GenLayer Studio on ' + short(target) + '.');
        }
        return { ok: false, error: code, contract: target };
      });
  }

  // getAudit(contractAddr) -> Promise<string|null>  (alias of getOnChain)
  function getAudit(contractAddr) {
    return getOnChain(contractAddr);
  }

  // ── v2 verified publish (analyze_verified) ─────────────────────────────────
  // The caller passes only pointers (target, chainId, blockNumber). The
  // validators fetch the code/block themselves; the returned record is bound to
  // that fetch (code_hash + block_hash). The verified badge is granted only when
  // the record read back carries a code_hash and a block_hash.
  function verifyRecordOnChain(client, target, contractAddr, id, record, expected, hash) {
    var net = getNetwork();
    var Verify = window.AuditAIGenLayerVerify;
    var verification;
    if (Verify && typeof Verify.verifyFinalizedOnChainState === 'function') {
      verification = Verify.verifyFinalizedOnChainState({
        action: 'analyze_verified',
        txHash: hash,
        contractAddress: contractAddr,
        networkId: net ? net.id : null,
        chainId: net ? net.chainId : null,
        submittedBy: expected.submittedBy || null,
        expected: { target: expected.target, chainId: expected.chainId, blockNumber: expected.blockNumber },
        state: { record: record }
      });
    } else {
      var hasCode = !!(record && record.code_hash);
      var hasBlock = !!(record && record.block_hash);
      verification = {
        verified: hasCode && hasBlock,
        status: (hasCode && hasBlock) ? 'VERIFIED_ON_CHAIN' : 'VERIFICATION_PENDING',
        matchedFields: [],
        mismatchFields: [],
        verifiedAt: (hasCode && hasBlock) ? Date.now() : null
      };
    }
    var explorerUrl = (Verify && typeof Verify.explorerTxUrl === 'function')
      ? Verify.explorerTxUrl(net ? net.id : null, hash)
      : null;
    return {
      ok: true,
      hash: hash,
      id: id,
      record: record,
      verified: verification.verified,
      verificationStatus: verification.status,
      onChain: verification.verified,
      matchedFields: verification.matchedFields || [],
      mismatchFields: verification.mismatchFields || [],
      contract: target,
      explorerUrl: explorerUrl
    };
  }

  // analyzeVerified(addr, chainId, blockNumber, opts) -> Promise
  //   opts: { account, onStatus, pollInterval, maxConsecutiveRpcErrors }
  //   resolves { ok, hash, id, record, verified, verificationStatus, onChain }
  //   only after FINALIZED + read + state verification.
  function analyzeVerified(addr, chainId, blockNumber, opts) {
    opts = opts || {};
    var target = getContract();
    if (!isSet(target)) {
      return Promise.resolve({ ok: false, needContract: true, message: 'No GenLayer contract set. Click the top-bar pill first.' });
    }
    var client = getClient();
    var account = opts.account;
    var args = [addr, String(chainId), String(blockNumber)];
    if (!client || typeof client.analyzeVerified !== 'function' || !account) {
      return Promise.resolve(fallbackResult(target, 'analyze_verified', addr, args, 'No wallet connected — the result was NOT verified on-chain. Copy the call below and run it in GenLayer Studio on ' + short(target) + '.'));
    }
    var expected = { target: String(addr).toLowerCase(), chainId: String(chainId), blockNumber: String(blockNumber), submittedBy: account };
    return client.analyzeVerified(addr, chainId, blockNumber, { account: account, onStatus: opts.onStatus })
      .then(function (outcome) {
        return verifyRecordOnChain(client, target, addr, outcome.id, outcome.record, expected, outcome.hash);
      })
      .catch(function (e) {
        var code = (e && e.message) || 'GENLAYER_ERROR';
        if (code === 'USER_REJECTED') {
          return fallbackResult(target, 'analyze_verified', addr, args, 'Signature canceled — the result was NOT verified on-chain. Copy the call below and run it in GenLayer Studio on ' + short(target) + '.');
        }
        return { ok: false, error: code, contract: target };
      });
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
    analyzeVerified: analyzeVerified,
    getAudit: getAudit,
    getClient: getClient,
    copyToClipboard: copyToClipboard
  };
})();
