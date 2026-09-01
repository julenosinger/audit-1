// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Network Registry & RPC Layer (Phase 6.5)
//
// The single source of truth for the EVM networks that can be *audited*. An
// audit always operates on `address + network`; the network determines where
// the bytecode comes from. This is deliberately SEPARATE from the GenLayer
// execution network (see public/genlayer-client.js) — the audited contract may
// live on Ethereum while the semantic audit runs on GenLayer Studionet.
//
// Responsibilities:
//   NETWORKS           — authoritative registry (chainId + RPC), no scattered ids
//   normalizeAddress   — validate EVM address format (never silently rewritten)
//   preflight          — verify eth_chainId against the selected network
//   getCode            — fetch bytecode via eth_getCode on the *selected* RPC
//   classifyContract   — CONTRACT / EOA / NOT_FOUND / NO_BYTECODE / RPC_ERROR /
//                        NETWORK_CHAIN_ID_MISMATCH / INVALID_ADDRESS
//   auditContext       — full validate → preflight → fetch → classify pipeline
//   cacheKey           — network-aware cache key (chainId:address)
//
// No external AI/security API. Only JSON-RPC (infrastructure for blockchain
// data). Deterministic and usable in both browser and Node (tests).
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAINetworks = api;
})(function () {
  'use strict';

  // ── Authoritative network registry (single source of truth) ───────────────
  // Order matters: discovery probes in this order. RPC URLs are the official /
  // public endpoints (existing project RPCs where available; BSC + Optimism use
  // public endpoints). Nothing is invented.
  var NETWORKS = {
    ethereum: {
      id: 'ethereum', name: 'Ethereum', chainId: 1,
      rpc: 'https://ethereum-rpc.publicnode.com',
      explorer: 'https://etherscan.io/address/', explorerName: 'Etherscan',
      type: 'mainnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: false, genLayerContract: '',
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }
    },
    bsc: {
      id: 'bsc', name: 'BNB Smart Chain', chainId: 56,
      rpc: 'https://bsc-rpc.publicnode.com',
      explorer: 'https://bscscan.com/address/', explorerName: 'BscScan',
      type: 'mainnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: false, genLayerContract: '',
      nativeCurrency: { name: 'BNB', symbol: 'BNB', decimals: 18 }
    },
    base: {
      id: 'base', name: 'Base', chainId: 8453,
      rpc: 'https://mainnet.base.org',
      explorer: 'https://basescan.org/address/', explorerName: 'BaseScan',
      type: 'mainnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: false, genLayerContract: '',
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }
    },
    arbitrum: {
      id: 'arbitrum', name: 'Arbitrum One', chainId: 42161,
      rpc: 'https://arb1.arbitrum.io/rpc',
      explorer: 'https://arbiscan.io/address/', explorerName: 'Arbiscan',
      type: 'mainnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: false, genLayerContract: '',
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }
    },
    optimism: {
      id: 'optimism', name: 'Optimism', chainId: 10,
      rpc: 'https://mainnet.optimism.io',
      explorer: 'https://optimistic.etherscan.io/address/', explorerName: 'Optimistic Etherscan',
      type: 'mainnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: false, genLayerContract: '',
      nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 }
    },
    genlayerStudionet: {
      id: 'genlayerStudionet', name: 'GenLayer Studionet', chainId: 61999,
      rpc: 'https://studio.genlayer.com/api',
      explorer: null, explorerName: null,
      type: 'testnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: true,
      genLayerContract: '0xF2c549Bf2Dc106a28354B1444298DD460601856B',
      nativeCurrency: { name: 'GEN', symbol: 'GEN', decimals: 18 }
    },
    genlayerBradbury: {
      id: 'genlayerBradbury', name: 'GenLayer Bradbury', chainId: 4221,
      rpc: 'https://rpc-bradbury.genlayer.com',
      explorer: null, explorerName: null,
      type: 'testnet', enabled: true, supportsLocalAudit: true, supportsGenLayer: true, genLayerContract: '',
      nativeCurrency: { name: 'GEN', symbol: 'GEN', decimals: 18 }
    }
  };

  var DEFAULT_NETWORK_ID = 'ethereum';
  var NETWORK_IDS = ['ethereum', 'bsc', 'base', 'arbitrum', 'optimism', 'genlayerStudionet', 'genlayerBradbury'];

  // GenLayer *audit* networks that map 1:1 onto a GenLayer execution network id.
  var GENLAYER_NETWORK_MAP = {
    genlayerStudionet: 'studionet',
    genlayerBradbury: 'bradbury'
  };

  function getNetwork(id) { return NETWORKS[id] || null; }
  function networkIds() { return NETWORK_IDS.slice(); }

  function networkByChainId(chainId) {
    var ids = NETWORK_IDS;
    for (var i = 0; i < ids.length; i++) {
      if (NETWORKS[ids[i]].chainId === chainId) return NETWORKS[ids[i]];
    }
    return null;
  }

  // ── Address validation / normalization ─────────────────────────────────────
  function isValidAddress(addr) {
    return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr.trim());
  }

  // Normalize to lowercase for storage keys / RPC. Never silently *rewrite* the
  // user's display value — the original is preserved by callers.
  function normalizeAddress(addr) {
    if (typeof addr !== 'string') return { valid: false, address: null };
    var s = addr.trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return { valid: false, address: null };
    return { valid: true, address: s.toLowerCase() };
  }

  // ── JSON-RPC (infrastructure for blockchain data only) ─────────────────────
  function doFetch(url, init) {
    if (typeof fetch === 'function') return fetch(url, init);
    if (typeof globalThis !== 'undefined' && typeof globalThis.fetch === 'function') return globalThis.fetch(url, init);
    return Promise.reject(new Error('fetch unavailable'));
  }

  async function jsonRpc(rpc, method, params) {
    var res = await doFetch(rpc, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: method, params: params || [] })
    });
    if (!res.ok) throw new Error('RPC_HTTP_' + res.status);
    var data = await res.json();
    if (data && data.error) throw new Error((data.error.message || 'RPC_ERROR'));
    return data && data.result;
  }

  function hexToInt(x) {
    if (x === null || x === undefined) return null;
    if (typeof x === 'number') return x;
    var s = String(x);
    if (s.slice(0, 2) === '0x' || s.slice(0, 2) === '0X') return parseInt(s.slice(2), 16);
    return parseInt(s, 10);
  }

  function hexLength(code) {
    if (code === null || code === undefined) return 0;
    var s = String(code).trim();
    if (s.slice(0, 2) === '0x' || s.slice(0, 2) === '0X') s = s.slice(2);
    return s.length / 2;
  }

  // ── Preflight ───────────────────────────────────────────────────────────────
  // Verify the RPC's eth_chainId matches the selected network before auditing.
  async function rpcChainId(rpc) {
    var raw = await jsonRpc(rpc, 'eth_chainId', []);
    return hexToInt(raw);
  }

  async function preflight(rpc, expectedChainId) {
    var expected = (typeof expectedChainId === 'number') ? expectedChainId : parseInt(expectedChainId, 10);
    try {
      var actual = await rpcChainId(rpc);
      if (actual !== expected) {
        return { ok: false, error: 'NETWORK_CHAIN_ID_MISMATCH', chainId: actual, expectedChainId: expected };
      }
      return { ok: true, chainId: actual, expectedChainId: expected };
    } catch (e) {
      return { ok: false, error: 'RPC_ERROR', detail: String((e && e.message) || e), chainId: null, expectedChainId: expected };
    }
  }

  // ── Bytecode fetch (network-aware cache) ────────────────────────────────────
  // Cache key MUST include chainId so the same address on two networks never
  // reuses each other's bytecode.
  function cacheKey(chainId, address) {
    return String(chainId) + ':' + String(address || '').toLowerCase();
  }

  var _codeCache = {}; // cacheKey -> { code: string }
  var _cacheEnabled = true;

  function setCacheEnabled(enabled) { _cacheEnabled = !!enabled; }

  function clearCodeCache() { _codeCache = {}; }

  function _getCodeUncached(rpc, address) {
    return jsonRpc(rpc, 'eth_getCode', [address, 'latest']);
  }

  async function getCode(rpc, address, chainId, opts) {
    opts = opts || {};
    var useCache = (opts.useCache === undefined) ? true : !!opts.useCache;
    var key = (chainId !== undefined && chainId !== null) ? cacheKey(chainId, address) : null;
    if (useCache && _cacheEnabled && key && _codeCache[key] !== undefined) {
      return _codeCache[key].code;
    }
    var code = await _getCodeUncached(rpc, address);
    if (useCache && _cacheEnabled && key) _codeCache[key] = { code: code };
    return code;
  }

  // Probe whether the address is a live account (nonce or balance nonzero) —
  // used to distinguish EOA (account exists, no code) from NOT_FOUND (no code,
  // no activity, address likely does not exist on this network).
  async function probeAccount(rpc, address) {
    try {
      var nonceRaw = await jsonRpc(rpc, 'eth_getTransactionCount', [address, 'latest']);
      var balanceRaw = await jsonRpc(rpc, 'eth_getBalance', [address, 'latest']);
      var nonce = hexToInt(nonceRaw);
      var balance = hexToInt(balanceRaw);
      var active = (nonce !== null && nonce > 0) || (balance !== null && balance > 0);
      return { ok: true, active: active, nonce: nonce, balance: balance };
    } catch (e) {
      return { ok: false, active: null, error: String((e && e.message) || e) };
    }
  }

  // ── Contract classification ─────────────────────────────────────────────────
  // Pure function: maps the observed context to a single classification. Empty
  // eth_getCode is NOT automatically EOA — the reason is determined from context.
  function classifyContract(code, opts) {
    opts = opts || {};
    if (opts.status === 'INVALID_ADDRESS') return 'INVALID_ADDRESS';
    if (opts.status === 'NETWORK_CHAIN_ID_MISMATCH') return 'NETWORK_CHAIN_ID_MISMATCH';
    if (opts.status === 'RPC_ERROR') return 'RPC_ERROR';
    if (hexLength(code) > 0) return 'CONTRACT';
    // empty code
    if (opts.accountActive === true) return 'EOA';
    if (opts.accountActive === false) return 'NOT_FOUND';
    return 'NO_BYTECODE';
  }

  // ── Full audit context pipeline ─────────────────────────────────────────────
  // validate address → preflight (eth_chainId) → fetch bytecode → classify.
  // Returns a network-aware context consumed by the Local Audit Engine. The
  // engine remains responsible for the actual analysis; this layer only decides
  // *where the bytecode comes from*.
  async function auditContext(networkId, address, opts) {
    opts = opts || {};
    var net = NETWORKS[networkId] || null;

    if (!net) {
      return {
        ok: false, error: 'UNKNOWN_NETWORK',
        networkId: networkId, networkName: null, chainId: null,
        contractType: 'RPC_ERROR', bytecodeAvailable: false, code: null,
        networkStatus: { rpc: 'unavailable', chainIdMatch: false, bytecode: 'not_checked' }
      };
    }

    var norm = normalizeAddress(address);
    if (!norm.valid) {
      return {
        ok: false, error: 'INVALID_ADDRESS',
        networkId: net.id, networkName: net.name, chainId: net.chainId,
        address: (typeof address === 'string' ? address : ''),
        contractType: 'INVALID_ADDRESS', bytecodeAvailable: false, code: null,
        networkStatus: { rpc: 'not_checked', chainIdMatch: false, bytecode: 'not_checked' }
      };
    }
    var normalized = norm.address;

    // 1. Preflight — verify chain id.
    var pf = await preflight(net.rpc, net.chainId);
    if (!pf.ok) {
      var pfType = (pf.error === 'NETWORK_CHAIN_ID_MISMATCH') ? 'NETWORK_CHAIN_ID_MISMATCH' : 'RPC_ERROR';
      return {
        ok: false, error: pf.error,
        networkId: net.id, networkName: net.name, chainId: net.chainId,
        actualChainId: pf.chainId,
        address: normalized,
        contractType: pfType, bytecodeAvailable: false, code: null,
        networkStatus: {
          rpc: (pf.error === 'RPC_ERROR') ? 'unavailable' : 'connected',
          chainIdMatch: false,
          bytecode: 'not_checked'
        }
      };
    }

    // 2. Fetch bytecode from the selected network's RPC (never a fallback).
    var code = null, rpcError = null;
    try {
      code = await getCode(net.rpc, normalized, net.chainId, opts);
    } catch (e) {
      rpcError = String((e && e.message) || e);
    }
    if (rpcError) {
      return {
        ok: false, error: 'RPC_ERROR', detail: rpcError,
        networkId: net.id, networkName: net.name, chainId: net.chainId,
        address: normalized,
        contractType: 'RPC_ERROR', bytecodeAvailable: false, code: null,
        networkStatus: { rpc: 'unavailable', chainIdMatch: true, bytecode: 'not_checked' }
      };
    }

    // 3. Classify. Empty code is probed to separate EOA from NOT_FOUND.
    var accountActive = null;
    if (hexLength(code) === 0) {
      var probe = await probeAccount(net.rpc, normalized);
      accountActive = probe.active;
    }
    var contractType = classifyContract(code, { accountActive: accountActive });
    var bytecodeAvailable = contractType === 'CONTRACT';

    return {
      ok: true, error: null,
      networkId: net.id, networkName: net.name, chainId: net.chainId,
      address: normalized,
      contractType: contractType,
      bytecodeAvailable: bytecodeAvailable,
      code: code,
      networkStatus: {
        rpc: 'connected',
        chainIdMatch: true,
        bytecode: bytecodeAvailable ? 'found' : (contractType === 'RPC_ERROR' ? 'not_checked' : 'not_found')
      }
    };
  }

  // ── Automatic contract-network discovery (Phase 7.1) ───────────────────────
  // Address → probe enabled networks (parallel, bounded concurrency, per-network
  // error isolation + timeout) → eth_getCode → classify. Never assumes Ethereum;
  // never silently falls back. Bytecode cache is keyed by chainId:address.
  function withTimeout(promise, ms) {
    return new Promise(function (resolve, reject) {
      var done = false;
      var t = setTimeout(function () { if (!done) { done = true; reject(new Error('TIMEOUT')); } }, ms);
      promise.then(function (v) { if (!done) { done = true; clearTimeout(t); resolve(v); } },
        function (e) { if (!done) { done = true; clearTimeout(t); reject(e); } });
    });
  }

  async function discoverContract(address, opts) {
    opts = opts || {};
    var norm = normalizeAddress(address);
    if (!norm.valid) {
      return { ok: false, error: 'INVALID_ADDRESS', found: false, matchCount: 0, matches: [], diagnostics: [], address: String(address || '') };
    }
    var normalized = norm.address;
    var timeoutMs = opts.timeoutMs || 8000;
    var concurrency = opts.concurrency || 4;
    var verifyChainId = (opts.verifyChainId === undefined) ? true : !!opts.verifyChainId;

    var ids = NETWORK_IDS.filter(function (id) { return NETWORKS[id].enabled !== false; });

    var results = [];
    var cursor = 0;
    var workers = [];
    var workerCount = Math.max(1, Math.min(concurrency, ids.length));
    for (var w = 0; w < workerCount; w++) {
      workers.push((function () {
        return (async function () {
          while (true) {
            var idx = cursor++;
            if (idx >= ids.length) break;
            var net = NETWORKS[ids[idx]];
            var entry = {
              networkId: net.id, networkName: net.name, chainId: net.chainId,
              explorer: net.explorer || null, explorerName: net.explorerName || null,
              contractType: 'RPC_ERROR', bytecodeAvailable: false, code: null, error: null
            };
            try {
              var code = await withTimeout(getCode(net.rpc, normalized, net.chainId, { useCache: true }), timeoutMs);
              if (hexLength(code) > 0) {
                if (verifyChainId) {
                  var actual = await withTimeout(rpcChainId(net.rpc), timeoutMs);
                  if (actual !== net.chainId) {
                    entry.contractType = 'NETWORK_CHAIN_ID_MISMATCH';
                    entry.error = 'chainId ' + actual + ' != ' + net.chainId;
                    results.push(entry);
                    continue;
                  }
                }
                entry.contractType = 'CONTRACT';
                entry.bytecodeAvailable = true;
                entry.code = code;
              } else {
                entry.contractType = 'NOT_FOUND';
              }
            } catch (e) {
              entry.contractType = 'RPC_ERROR';
              entry.error = String((e && e.message) || e);
            }
            results.push(entry);
          }
        })();
      })());
    }
    await Promise.all(workers);

    var byId = {};
    results.forEach(function (r) { byId[r.networkId] = r; });
    var ordered = ids.map(function (id) { return byId[id]; }).filter(Boolean);

    var matches = ordered.filter(function (r) { return r.contractType === 'CONTRACT'; });

    return {
      ok: true,
      found: matches.length > 0,
      matchCount: matches.length,
      matches: matches,
      diagnostics: ordered,
      address: normalized
    };
  }

  return {
    NETWORKS: NETWORKS,
    DEFAULT_NETWORK_ID: DEFAULT_NETWORK_ID,
    GENLAYER_NETWORK_MAP: GENLAYER_NETWORK_MAP,
    getNetwork: getNetwork,
    networkIds: networkIds,
    networkByChainId: networkByChainId,
    isValidAddress: isValidAddress,
    normalizeAddress: normalizeAddress,
    hexToInt: hexToInt,
    hexLength: hexLength,
    jsonRpc: jsonRpc,
    rpcChainId: rpcChainId,
    preflight: preflight,
    getCode: getCode,
    cacheKey: cacheKey,
    setCacheEnabled: setCacheEnabled,
    clearCodeCache: clearCodeCache,
    probeAccount: probeAccount,
    classifyContract: classifyContract,
    auditContext: auditContext,
    discoverContract: discoverContract,
    withTimeout: withTimeout
  };
});
