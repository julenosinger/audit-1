// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Contract Studio (Phase 7.2, Contract Studio 2.0)
//
// Orchestrates the contract-creation experience: type selection, guided
// configuration, preview assembly, and the full build pipeline (templates +
// security review + hashes + capability). This module owns NO templates and NO
// security rules — it delegates to contract-templates.js and contract-security.js.
//
// Works in browser and Node. No external AI/security API, no deployment.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIContractStudio = api;
})(function () {
  'use strict';

  function templates() {
    return (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIContractTemplates;
  }
  function security() {
    return (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIContractSecurity;
  }

  // ── Chat → contract-type detection ─────────────────────────────────────────
  function detectCreateType(text) {
    var t = String(text || '').toLowerCase();
    if (/erc-?1155|erc1155/.test(t)) return 'erc1155';
    if (/erc-?721|erc721|nft/.test(t)) return 'erc721';
    if (/erc-?20|erc20|token\b/.test(t)) return 'erc20';
    if (/escrow/.test(t)) return 'escrow';
    if (/stak/.test(t)) return 'staking';
    if (/vest/.test(t)) return 'vesting';
    if (/treasury/.test(t)) return 'treasury';
    if (/timelock|time lock/.test(t)) return 'timelock';
    if (/genlayer|intelligent contract|ai decision/.test(t)) return 'genlayer_intelligent';
    return null; // unknown → let the UI show the type menu
  }

  // ── Guided configuration questions (only the necessary parameters) ────────
  function guidedQuestions(type) {
    switch (type) {
      case 'erc20':
        return [
          { key: 'name', label: 'What should the token be called?', kind: 'text' },
          { key: 'symbol', label: 'What is its symbol?', kind: 'text' },
          { key: 'supply', label: 'What is the initial supply?', kind: 'number' },
          { key: 'supplyType', label: 'Fixed supply or mintable?', kind: 'choice', choices: ['fixed', 'mintable'] },
          { key: 'burn', label: 'Burnable?', kind: 'boolean' },
          { key: 'pause', label: 'Pausable?', kind: 'boolean' },
          { key: 'accessControl', label: 'Access control?', kind: 'choice', choices: ['none', 'ownable', 'accesscontrol'] }
        ];
      case 'erc721':
        return [
          { key: 'name', label: 'Collection name?', kind: 'text' },
          { key: 'symbol', label: 'Symbol?', kind: 'text' },
          { key: 'baseURI', label: 'Base URI?', kind: 'text' },
          { key: 'burn', label: 'Burnable?', kind: 'boolean' },
          { key: 'accessControl', label: 'Access control?', kind: 'choice', choices: ['none', 'ownable'] }
        ];
      case 'erc1155':
        return [
          { key: 'name', label: 'Collection name?', kind: 'text' },
          { key: 'uri', label: 'Metadata URI?', kind: 'text' },
          { key: 'burn', label: 'Burnable?', kind: 'boolean' },
          { key: 'accessControl', label: 'Access control?', kind: 'choice', choices: ['none', 'ownable'] }
        ];
      case 'escrow':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'assetType', label: 'Asset type (native or ERC-20)?', kind: 'choice', choices: ['native', 'erc20'] },
          { key: 'amount', label: 'Escrow amount?', kind: 'number' },
          { key: 'timeout', label: 'Timeout (seconds)?', kind: 'number' }
        ];
      case 'staking':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'lockPeriod', label: 'Lock period (seconds)?', kind: 'number' },
          { key: 'rewardModel', label: 'Reward model?', kind: 'choice', choices: ['unconfigured', 'fixed-rate'] }
        ];
      case 'vesting':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'totalAmount', label: 'Total amount?', kind: 'number' },
          { key: 'cliff', label: 'Cliff (seconds)?', kind: 'number' },
          { key: 'duration', label: 'Duration (seconds)?', kind: 'number' },
          { key: 'revocable', label: 'Revocable?', kind: 'boolean' }
        ];
      case 'treasury':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'spendingLimit', label: 'Spending limit?', kind: 'number' }
        ];
      case 'timelock':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'minDelay', label: 'Minimum delay (seconds)?', kind: 'number' }
        ];
      case 'genlayer_intelligent':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'description', label: 'Short description?', kind: 'text' }
        ];
      case 'genlayer_ai':
        return [
          { key: 'name', label: 'Contract name?', kind: 'text' },
          { key: 'description', label: 'Short description?', kind: 'text' }
        ];
      default:
        return [];
    }
  }

  // ── Full build pipeline ────────────────────────────────────────────────────
  // spec → validate → generate → security review → hashes. Deterministic.
  function build(spec) {
    var T = templates();
    var S = security();
    var fullSpec = Object.assign({}, T.defaultSpec(spec.type), spec || {});
    var validation = T.validateSpec(fullSpec);
    if (!validation.valid) {
      return { ok: false, spec: fullSpec, validation: validation, source: null, review: null, hashes: null };
    }
    var source = T.generateSource(fullSpec);
    var review = S ? S.review(fullSpec, source) : null;
    var hashes = {
      builderVersion: T.BUILDER_VERSION,
      contractType: fullSpec.type,
      specHash: T.specHash(fullSpec),
      sourceHash: T.sourceHash(source)
    };
    return { ok: true, spec: fullSpec, validation: validation, source: source, review: review, hashes: hashes };
  }

  // ── Capability resolution against a network descriptor ─────────────────────
  // network: { id, name, chainId, family: 'EVM' | 'GENLAYER' }
  function capabilityFor(buildResult, network) {
    var T = templates();
    if (!buildResult || !buildResult.ok) return { supported: false, reason: 'NOT_SUPPORTED: specification is invalid' };
    return T.deploymentCapability(buildResult.spec, network ? network.family : null);
  }

  return {
    detectCreateType: detectCreateType,
    guidedQuestions: guidedQuestions,
    build: build,
    capabilityFor: capabilityFor
  };
});
