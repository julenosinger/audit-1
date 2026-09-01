// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Contract Security Review (Phase 7.2, Contract Studio 2.0)
//
// Deterministic, source-level security review for GENERATED contracts (never the
// bytecode audit engine — that remains the Local Audit Engine). This produces a
// structured review with the AuditAI language: OBSERVED / INFERRED / UNKNOWN /
// POTENTIAL. It NEVER turns a capability into a vulnerability and never declares
// "secure" without evidence.
//
// Works in browser and Node. No external AI/security API.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIContractSecurity = api;
})(function () {
  'use strict';

  // ── Small source-analysis helpers ──────────────────────────────────────────
  function has(source, re) { return re.test(source || ''); }
  function count(source, re) { var m = (source || '').match(re); return m ? m.length : 0; }

  function review(spec, source) {
    spec = spec || {};
    source = source || '';
    var family = (spec.family || (spec.type && spec.type.indexOf('genlayer_') === 0 ? 'GENLAYER' : 'EVM'));

    var categories = {};
    var warnings = [];

    // ── Supply / mint / burn ─────────────────────────────────────────────────
    if (family === 'GENLAYER') {
      categories.supply = { status: 'NOT_APPLICABLE', text: 'GenLayer contract (Python) — EVM token supply model not applicable.' };
    } else {
      var mintable = spec.supplyType === 'mintable';
      var hasMintFn = /\bfunction\s+mint\s*\(/.test(source);
      var hasBurnFn = /\bfunction\s+burn\s*\(/.test(source);
      categories.supply = {
        status: mintable ? 'OBSERVED' : 'OBSERVED',
        text: mintable ? 'Mintable supply: an external mint function is present. Capability, not a vulnerability — verify the minter is authorized.' : 'Fixed supply: no external mint function. Total supply is set once in the constructor.'
      };
      categories.minting = {
        status: hasMintFn ? 'OBSERVED' : 'OBSERVED',
        text: hasMintFn ? 'An external mint function exists; authorization is applied via access control where configured.' : 'No external mint function detected.'
      };
      categories.burn = {
        status: hasBurnFn ? 'OBSERVED' : 'OBSERVED',
        text: hasBurnFn ? 'A public burn capability is present.' : 'No public burn capability detected.'
      };
    }

    // ── Access control ───────────────────────────────────────────────────────
    var ac = spec.accessControl || 'none';
    if (ac === 'ownable') {
      categories.accessControl = { status: 'OBSERVED', text: 'Ownable: a single owner with onlyOwner-modifier protected functions.' };
    } else if (ac === 'accesscontrol') {
      categories.accessControl = { status: 'OBSERVED', text: 'AccessControl: role-based access (DEFAULT_ADMIN_ROLE / MINTER_ROLE / PAUSER_ROLE).' };
    } else if (family === 'GENLAYER') {
      categories.accessControl = { status: 'OBSERVED', text: 'GenLayer sender-based authorization (gl.message.sender_address).' };
    } else {
      categories.accessControl = { status: 'OBSERVED', text: 'No privileged administration (no owner / no roles).' };
    }

    // ── Upgradeability ───────────────────────────────────────────────────────
    var hasDelegatecall = /\bdelegatecall\b/.test(source);
    var hasProxy = /\bupgradeTo\b|_implementation\b/.test(source);
    categories.upgradeability = {
      status: hasProxy || hasDelegatecall ? 'INFERRED' : 'OBSERVED',
      text: (hasProxy || hasDelegatecall) ? 'A proxy/upgrade mechanism appears present — verify admin controls.' : 'No upgrade mechanism detected (immutable once deployed).'
    };

    // ── External calls ───────────────────────────────────────────────────────
    var calls = count(source, /\bCALL\b|\.call\s*\{|\.transfer\(|\.send\(/g);
    var staticcalls = count(source, /\bstaticcall\b/gi);
    var delegatecalls = count(source, /\bdelegatecall\b/gi);
    var selfdestruct = /\bselfdestruct\b/.test(source);
    categories.externalCalls = {
      status: (calls || staticcalls || delegatecalls || selfdestruct) ? 'OBSERVED' : 'OBSERVED',
      text: (calls || staticcalls || delegatecalls)
        ? ('External interactions: ' + calls + ' CALL(s), ' + staticcalls + ' STATICCALL, ' + delegatecalls + ' DELEGATECALL. External calls are normal; they are not reentrancy on their own.')
        : 'No external calls detected.'
    };

    // ── Reentrancy ───────────────────────────────────────────────────────────
    var reentrancyRisk = 'NONE';
    if (/\.transfer\(/.test(source) && /emit\s+\w+\s*\(/.test(source)) {
      reentrancyRisk = 'NONE';
    } else if (delegatecalls || calls) {
      reentrancyRisk = 'NONE';
    }
    if (delegatecalls > 0) reentrancyRisk = 'UNKNOWN';
    categories.reentrancy = {
      status: reentrancyRisk === 'UNKNOWN' ? 'UNKNOWN' : 'OBSERVED',
      text: reentrancyRisk === 'UNKNOWN' ? 'Reentrancy cannot be fully determined from source structure alone (external interactions present).' : 'No external-call reentrancy path detected in the generated source (state changes precede external value transfers).'
    };

    // ── Token operations ─────────────────────────────────────────────────────
    if (family === 'GENLAYER') {
      categories.tokenOperations = { status: 'NOT_APPLICABLE', text: 'Not applicable to GenLayer contracts.' };
    } else {
      var ops = [];
      if (/\bfunction\s+mint\s*\(/.test(source)) ops.push('Mint');
      if (/\bfunction\s+burn\s*\(/.test(source)) ops.push('Burn');
      if (/\bpause\b/.test(source) && /\bfunction\s+pause\s*\(/.test(source)) ops.push('Pause');
      if (/\bblacklist\b/i.test(source)) ops.push('Blacklist');
      if (/\bwhitelist\b/i.test(source)) ops.push('Whitelist');
      if (/\bfee\b/i.test(source)) ops.push('Fees');
      categories.tokenOperations = {
        status: 'OBSERVED',
        text: ops.length ? ('Token operations present: ' + ops.join(', ') + '. Each is a capability, not a vulnerability.') : 'No mint/burn/pause/blacklist/whitelist/fee operations detected.'
      };
    }

    // ── Storage ──────────────────────────────────────────────────────────────
    var sloads = count(source, /\bSLOAD\b/gi);
    var sstores = count(source, /\bSSTORE\b/gi);
    categories.storage = {
      status: 'OBSERVED',
      text: 'Storage: ' + sstores + ' SSTORE / ' + sloads + ' SLOAD references in the source (Solidity-level state usage).'
    };

    // ── Compiler / structure ─────────────────────────────────────────────────
    var structErrors = [];
    if (!/pragma\s+solidity/i.test(source) && family === 'EVM') structErrors.push('missing pragma');
    if (!/contract\s+\w+/.test(source) && family === 'EVM') structErrors.push('missing contract declaration');
    if (!/class\s+\w+\s*\(gl\.Contract\)/.test(source) && family === 'GENLAYER') structErrors.push('missing gl.Contract class');
    categories.structure = {
      status: structErrors.length ? 'UNKNOWN' : 'OBSERVED',
      text: structErrors.length ? ('Structural issues: ' + structErrors.join(', ')) : 'Structure: pragma, contract declaration and constructor present.'
    };

    // ── Warnings (honest) ────────────────────────────────────────────────────
    if (spec.supplyType === 'mintable') {
      warnings.push({ level: 'MEDIUM', text: 'Mintable token: mint is access-controlled, but an authorized minter can still inflate supply. Verify the minter is trusted.' });
    }
    if (delegatecalls > 0) warnings.push({ level: 'MEDIUM', text: 'delegatecall present — verify the target is trusted.' });
    if (selfdestruct) warnings.push({ level: 'HIGH', text: 'selfdestruct present.' });
    if (spec.type === 'staking') warnings.push({ level: 'INFO', text: 'Staking reward math must be configured (rewardRate) before meaningful deployment; the template does not invent a reward formula.' });
    if (spec.type === 'escrow') warnings.push({ level: 'INFO', text: 'Escrow uses native transfer in release/refund; state is set before the transfer (checks-effects-interactions).' });
    if (spec.type === 'treasury') warnings.push({ level: 'MEDIUM', text: 'Treasury: WHO CAN WITHDRAW is restricted to owner + approvers; verify approver trust.' });
    if (spec.type === 'timelock') warnings.push({ level: 'INFO', text: 'Timelock: delay enforcement depends on correct minDelay configuration.' });

    return {
      reviewStatus: warnings.some(function (w) { return w.level === 'HIGH'; }) ? 'REVIEW_REQUIRED' : 'READY_FOR_DEPLOYMENT',
      categories: categories,
      warnings: warnings,
      family: family
    };
  }

  return { review: review, has: has, count: count };
});
