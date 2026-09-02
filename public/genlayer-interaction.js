// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — GenLayer Contract Interaction (Phase 7.6)
//
// Pure, deterministic logic + SDK orchestration for interacting with REAL
// GenLayer Intelligent Contracts (Studionet + Bradbury). It NEVER uses
// eth_getCode, never fabricates a schema/ABI/result/txHash, and never signs or
// writes without explicit confirmation.
//
// Responsibilities:
//   BRADBURY / ERRORS / TX_STATES — canonical network + error/state taxonomy
//   parseContractSchema            — turn a real SDK ContractSchema into
//                                    read/write function descriptors
//   assertContractNetworkPair      — never cross-pair network + contract
//   reviewGenLayerContract         — GENLAYER_SOURCE_REVIEW (UNKNOWN ⇒ null score)
//   uniqueFindingIds               — deterministic, duplicate-free finding IDs
//   inspectContract                — real getContractSchema + getContractCode
//   runRead / runSimulate / runWrite — real read/simulate/write (write guarded)
//
// Works in browser and Node (tests). The GenLayer client is injected so tests
// can use a real SDK shape with a mocked transport — never a fake result.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerInteraction = api;
})(function () {
  'use strict';

  // ── Real Bradbury Testnet configuration (single source of truth) ────────────
  var BRADBURY = {
    id: 'bradbury',
    networkId: 'bradbury',
    name: 'Bradbury Testnet',
    chainId: 4221,
    rpc: 'https://rpc-bradbury.genlayer.com',
    explorer: 'https://explorer-bradbury.genlayer.com/',
    contract: '0x119Ac58AF8546Df0B0E55eB24277C756d9458000',
    deploymentTx: '0x79b33023be587678e6419526462209168598a1b5b20279dc45ef904b5561cabc'
  };

  // ── Explicit error taxonomy (never hide a real error behind a generic one) ──
  var ERRORS = {
    BRADBURY_RPC_UNAVAILABLE: 'BRADBURY_RPC_UNAVAILABLE',
    BRADBURY_CONTRACT_NOT_FOUND: 'BRADBURY_CONTRACT_NOT_FOUND',
    BRADBURY_SCHEMA_UNAVAILABLE: 'BRADBURY_SCHEMA_UNAVAILABLE',
    BRADBURY_READ_FAILED: 'BRADBURY_READ_FAILED',
    BRADBURY_SIMULATION_FAILED: 'BRADBURY_SIMULATION_FAILED',
    BRADBURY_WRITE_REJECTED: 'BRADBURY_WRITE_REJECTED',
    BRADBURY_WRITE_FAILED: 'BRADBURY_WRITE_FAILED',
    BRADBURY_NETWORK_MISMATCH: 'BRADBURY_NETWORK_MISMATCH',
    BRADBURY_WALLET_REQUIRED: 'BRADBURY_WALLET_REQUIRED',
    BRADBURY_TX_PENDING: 'BRADBURY_TX_PENDING',
    BRADBURY_TX_FAILED: 'BRADBURY_TX_FAILED',
    CONTRACT_NETWORK_MISMATCH: 'CONTRACT_NETWORK_MISMATCH',
    GENLAYER_OPERATION_UNAVAILABLE: 'GENLAYER_OPERATION_UNAVAILABLE',
    SCHEMA_UNAVAILABLE: 'SCHEMA_UNAVAILABLE',
    WALLET_REQUIRED: 'WALLET_REQUIRED'
  };

  // ── Transaction lifecycle states (real transitions only) ────────────────────
  var TX_STATES = [
    'PREPARING',
    'SIMULATING',
    'AWAITING_SIGNATURE',
    'SUBMITTED',
    'CONFIRMING',
    'CONFIRMED',
    'FAILED',
    'UNKNOWN'
  ];

  function clientModule() {
    return (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerClient || null;
  }

  function normalizeAddr(addr) {
    return (typeof addr === 'string') ? addr.trim().toLowerCase() : '';
  }

  function knownContractFor(addr) {
    var m = clientModule();
    if (m && typeof m.knownContractFor === 'function') return m.knownContractFor(addr);
    var key = normalizeAddr(addr);
    if (key === normalizeAddr(BRADBURY.contract)) {
      return {
        networkId: 'bradbury', network: 'bradbury', name: BRADBURY.name,
        chainId: BRADBURY.chainId, address: BRADBURY.contract, deploymentTx: BRADBURY.deploymentTx
      };
    }
    return null;
  }

  // ── Network + contract pairing guard ────────────────────────────────────────
  // networkId + chainId + contractAddress are inseparable context. Delegates to
  // the client registry when available; otherwise uses the local BRADBURY map.
  function assertContractNetworkPair(opts) {
    opts = opts || {};
    var m = clientModule();
    if (m && typeof m.assertContractNetworkPair === 'function') {
      return m.assertContractNetworkPair(opts);
    }
    var networkId = opts.networkId || null;
    var chainId = opts.chainId;
    var address = opts.address || null;

    if (networkId === 'bradbury') {
      if (chainId !== undefined && chainId !== null && Number(chainId) !== BRADBURY.chainId) {
        return { ok: false, error: 'CONTRACT_NETWORK_MISMATCH', networkId: networkId, chainId: chainId, address: address, expectedChainId: BRADBURY.chainId };
      }
      if (address) {
        var known = knownContractFor(address);
        if (known && known.networkId !== 'bradbury') {
          return { ok: false, error: 'CONTRACT_NETWORK_MISMATCH', networkId: networkId, chainId: BRADBURY.chainId, address: address, expectedNetworkId: known.networkId };
        }
      }
      return { ok: true, networkId: 'bradbury', chainId: BRADBURY.chainId, address: address, known: knownContractFor(address) };
    }

    if (!networkId) return { ok: false, error: 'UNKNOWN_NETWORK', networkId: networkId, chainId: chainId, address: address };
    return { ok: true, networkId: networkId, chainId: chainId, address: address, known: null };
  }

  // ── Schema type description (deterministic, from the real SDK schema) ───────
  function describeType(t) {
    if (t === null || t === undefined) return 'any';
    if (typeof t === 'string') return t;
    if (Array.isArray(t)) {
      if (!t.length) return 'array';
      return '[' + t.map(describeType).join(' | ') + ']';
    }
    if (typeof t === 'object') {
      if (t.$or) return Array.isArray(t.$or) ? t.$or.map(describeType).join(' | ') : describeType(t.$or);
      if (t.$dict) return 'dict<' + describeType(t.$dict) + '>';
      if (t.$rep) return describeType(t.$rep) + '[]';
      var keys = Object.keys(t);
      if (keys.length) {
        return '{ ' + keys.map(function (k) { return k + ': ' + describeType(t[k]); }).join(', ') + ' }';
      }
      return 'object';
    }
    return 'any';
  }

  function describeParams(params) {
    if (!Array.isArray(params)) return [];
    return params.map(function (p) {
      if (Array.isArray(p) && p.length >= 2) return { name: String(p[0]), type: describeType(p[1]) };
      if (p && typeof p === 'object' && p.name) return { name: String(p.name), type: describeType(p.type) };
      return { name: 'arg', type: describeType(p) };
    });
  }

  // Turn a real SDK ContractSchema into read/write function descriptors. Never
  // invents functions: only what the schema actually exposes is returned.
  function parseContractSchema(schema) {
    if (!schema || typeof schema !== 'object' || !schema.methods || typeof schema.methods !== 'object') {
      return { available: false, readFunctions: [], writeFunctions: [], error: ERRORS.SCHEMA_UNAVAILABLE };
    }
    var readFunctions = [];
    var writeFunctions = [];
    Object.keys(schema.methods).forEach(function (name) {
      var m = schema.methods[name];
      if (!m || typeof m !== 'object') return;
      var fn = {
        name: name,
        params: describeParams(m.params),
        kwparams: m.kwparams ? Object.keys(m.kwparams).map(function (k) { return { name: k, type: describeType(m.kwparams[k]) }; }) : [],
        returns: describeType(m.ret),
        readonly: !!m.readonly,
        payable: !!m.payable
      };
      if (fn.readonly) readFunctions.push(fn); else writeFunctions.push(fn);
    });
    return {
      available: true,
      readFunctions: readFunctions,
      writeFunctions: writeFunctions,
      error: null
    };
  }

  // ── Finding ID determinism ──────────────────────────────────────────────────
  // All findings get unique IDs (src-001, src-002, …). Duplicates are resolved
  // deterministically; no two findings ever share an id.
  function uniqueFindingIds(findings) {
    var used = {};
    var out = [];
    var n = 0;
    (findings || []).forEach(function (f) {
      var base = f && f.id;
      var id = base || ('src-' + String(n + 1).padStart(3, '0'));
      while (used[id]) { n += 1; id = 'src-' + String(n + 1).padStart(3, '0'); }
      used[id] = true;
      n += 1;
      out.push(Object.assign({}, f, { id: id }));
    });
    return out;
  }

  // UNKNOWN risk must never carry a reassuring numeric score.
  function normalizeScore(risk, score) {
    if (risk === 'UNKNOWN') return null;
    return (score === undefined || score === null) ? null : score;
  }

  // ── GENLAYER_SOURCE_REVIEW (never EVM_BYTECODE_AUDIT) ──────────────────────
  // Produces an honest source/schema-based review result. Only observations that
  // are actually available are included; nothing is invented.
  function reviewGenLayerContract(opts) {
    opts = opts || {};
    var networkId = opts.networkId || null;
    var networkName = opts.networkName || null;
    var chainId = opts.chainId;
    var address = opts.address || null;
    var txHash = opts.txHash || null;

    var findings = uniqueFindingIds(opts.findings || []);
    var sourceAvailable = typeof opts.source === 'string' && opts.source.trim().length > 0;
    var schemaAvailable = !!(opts.schema && opts.schema.methods);

    var risk = opts.risk || 'UNKNOWN';
    var confidence = opts.confidence || 'LOW';
    var score = normalizeScore(risk, opts.score);

    return {
      auditType: 'GENLAYER_SOURCE_REVIEW',
      networkId: networkId,
      networkName: networkName || (networkId === 'bradbury' ? BRADBURY.name : (networkId || 'GenLayer')),
      chainId: chainId,
      address: address,
      txHash: txHash,
      risk: risk,
      confidence: confidence,
      score: score,
      verdict: risk === 'UNKNOWN' ? 'UNKNOWN' : 'POTENTIAL_VULNERABILITY',
      findings: findings,
      analysis: {
        sourceAvailable: sourceAvailable,
        schemaAvailable: schemaAvailable,
        source: opts.source || null,
        review: opts.review || null,
        contractType: opts.contractType || null
      },
      summary: opts.summary || ('GenLayer intelligent contract — source/schema-based security review.' +
        (sourceAvailable ? '' : ' Contract source was not available; only schema/structure was reviewed.'))
    };
  }

  // ── Real contract inspection (never eth_getCode) ───────────────────────────
  async function inspectContract(client, opts) {
    opts = opts || {};
    var address = opts.address;
    var networkId = opts.networkId || null;
    var chainId = opts.chainId;

    var pair = assertContractNetworkPair({ networkId: networkId, chainId: chainId, address: address });
    if (!pair.ok) return { ok: false, error: pair.error, networkId: networkId, chainId: chainId, address: address, schemaAvailable: false, codeAvailable: false, readFunctions: [], writeFunctions: [] };

    if (!client) return { ok: false, error: ERRORS.GENLAYER_OPERATION_UNAVAILABLE, networkId: networkId, chainId: chainId, address: address, schemaAvailable: false, codeAvailable: false, readFunctions: [], writeFunctions: [] };

    var schema = null, schemaError = null;
    var code = null, codeError = null;

    try { schema = await client.getContractSchema(address); }
    catch (e) { schemaError = String((e && e.message) || e); }

    try { code = await client.getContractCode(address); }
    catch (e) { codeError = String((e && e.message) || e); }

    var parsed = parseContractSchema(schema);

    return {
      ok: parsed.available,
      error: parsed.available ? null : (schemaError ? ERRORS.BRADBURY_SCHEMA_UNAVAILABLE : ERRORS.SCHEMA_UNAVAILABLE),
      detail: schemaError || null,
      networkId: networkId,
      chainId: chainId,
      address: address,
      schemaAvailable: parsed.available,
      codeAvailable: typeof code === 'string' && code.length > 0,
      code: code,
      codeError: codeError || null,
      readFunctions: parsed.readFunctions,
      writeFunctions: parsed.writeFunctions
    };
  }

  // ── Real read-only call (no wallet, no signature) ──────────────────────────
  async function runRead(client, opts) {
    opts = opts || {};
    var address = opts.address;
    var networkId = opts.networkId || null;
    var chainId = opts.chainId;
    var functionName = opts.functionName;
    var args = opts.args || [];

    if (!client) return { ok: false, error: ERRORS.GENLAYER_OPERATION_UNAVAILABLE, functionName: functionName };
    if (!functionName) return { ok: false, error: 'INVALID_FUNCTION', functionName: functionName };

    try {
      var result = await client.read(address, functionName, args);
      return {
        ok: true, error: null,
        functionName: functionName, args: args, result: result,
        networkId: networkId, chainId: chainId, address: address,
        timestamp: Date.now()
      };
    } catch (e) {
      return { ok: false, error: ERRORS.BRADBURY_READ_FAILED, detail: String((e && e.message) || e), functionName: functionName, networkId: networkId, chainId: chainId, address: address };
    }
  }

  // ── Real write simulation (read-only; no signature, no transaction) ────────
  async function runSimulate(client, opts) {
    opts = opts || {};
    var address = opts.address;
    var networkId = opts.networkId || null;
    var chainId = opts.chainId;
    var functionName = opts.functionName;
    var args = opts.args || [];

    if (!client) return { ok: false, error: ERRORS.GENLAYER_OPERATION_UNAVAILABLE, functionName: functionName };
    if (!functionName) return { ok: false, error: 'INVALID_FUNCTION', functionName: functionName };
    if (typeof client.simulateWriteContract !== 'function') {
      return { ok: false, error: ERRORS.GENLAYER_OPERATION_UNAVAILABLE, functionName: functionName };
    }

    try {
      var result = await client.simulateWriteContract(address, functionName, args);
      return { ok: true, error: null, functionName: functionName, args: args, result: result, networkId: networkId, chainId: chainId, address: address, timestamp: Date.now() };
    } catch (e) {
      return { ok: false, error: ERRORS.BRADBURY_SIMULATION_FAILED, detail: String((e && e.message) || e), functionName: functionName, networkId: networkId, chainId: chainId, address: address };
    }
  }

  // Wallet + network safety guard before any write. Never signs, never switches
  // silently — this only validates and reports.
  function validateWrite(opts) {
    opts = opts || {};
    var wallet = opts.wallet || null;
    var walletConnected = !!(wallet && wallet.address);
    var walletChainId = wallet && wallet.chainId;
    var targetChainId = opts.chainId;

    if (!walletConnected) return { ok: false, error: ERRORS.BRADBURY_WALLET_REQUIRED };
    if (targetChainId !== undefined && targetChainId !== null && String(walletChainId) !== String(targetChainId)) {
      return { ok: false, error: ERRORS.BRADBURY_NETWORK_MISMATCH, walletChainId: walletChainId, targetChainId: targetChainId };
    }
    return { ok: true, error: null };
  }

  // ── Real write (guarded; requires explicit confirmation) ───────────────────
  async function runWrite(client, opts) {
    opts = opts || {};
    var address = opts.address;
    var networkId = opts.networkId || null;
    var chainId = opts.chainId;
    var functionName = opts.functionName;
    var args = opts.args || [];
    var wallet = opts.wallet || null;

    // Hard gate: never write without explicit user confirmation.
    if (opts.confirmed !== true) {
      return { ok: false, error: ERRORS.BRADBURY_WRITE_REJECTED, functionName: functionName };
    }

    var guard = validateWrite({ wallet: wallet, chainId: chainId });
    if (!guard.ok) return { ok: false, error: guard.error, functionName: functionName, networkId: networkId, chainId: chainId };

    if (!client) return { ok: false, error: ERRORS.GENLAYER_OPERATION_UNAVAILABLE, functionName: functionName };
    if (typeof client.writeContract !== 'function') return { ok: false, error: ERRORS.GENLAYER_OPERATION_UNAVAILABLE, functionName: functionName };

    try {
      var hash = await client.writeContract(address, functionName, args, { account: wallet.address });
      return {
        ok: true, error: null,
        txHash: hash,
        contractAddress: address,
        networkId: networkId, network: networkId,
        chainId: chainId,
        functionName: functionName,
        parameters: args,
        status: 'SUBMITTED',
        timestamp: Date.now()
      };
    } catch (e) {
      return { ok: false, error: ERRORS.BRADBURY_WRITE_FAILED, detail: String((e && e.message) || e), functionName: functionName, networkId: networkId, chainId: chainId, address: address };
    }
  }

  return {
    BRADBURY: BRADBURY,
    ERRORS: ERRORS,
    TX_STATES: TX_STATES,
    knownContractFor: knownContractFor,
    assertContractNetworkPair: assertContractNetworkPair,
    describeType: describeType,
    describeParams: describeParams,
    parseContractSchema: parseContractSchema,
    uniqueFindingIds: uniqueFindingIds,
    normalizeScore: normalizeScore,
    reviewGenLayerContract: reviewGenLayerContract,
    inspectContract: inspectContract,
    runRead: runRead,
    runSimulate: runSimulate,
    validateWrite: validateWrite,
    runWrite: runWrite
  };
});
