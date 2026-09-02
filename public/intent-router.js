// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Intent Router & Context Engine (Phase 7.4)
//
// Centralizes the intelligence behind the Quick Actions and the Chat so both
// share the SAME handlers. It reasons about: intent, context, network family
// (EVM read-only vs GenLayer), capability (read/write, wallet requirement), and
// the next best action. It NEVER fabricates data — unknown fields stay null.
//
// This module is pure logic (no DOM, no deployment, no fabrication) and is
// testable in Node. The UI (index.html) consumes it.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIIntentRouter = api;
})(function () {
  'use strict';

  var INTENTS = {
    AUDIT_CONTRACT: 'AUDIT_CONTRACT',
    CREATE_CONTRACT: 'CREATE_CONTRACT',
    VIEW_PORTFOLIO: 'VIEW_PORTFOLIO',
    CHECK_APPROVALS: 'CHECK_APPROVALS',
    EXPLAIN_FINDINGS: 'EXPLAIN_FINDINGS',
    ASSESS_APPROVAL: 'ASSESS_APPROVAL',
    INSPECT_CONTRACT: 'INSPECT_CONTRACT',
    INTERACT_CONTRACT: 'INTERACT_CONTRACT'
  };

  function networks() {
    return (typeof globalThis !== 'undefined' ? globalThis : window).AuditAINetworks || null;
  }

  // 'GENLAYER' | 'EVM' | 'UNKNOWN' — derived from the registry's family model.
  function networkFamily(networkId) {
    if (networkId === 'genlayerStudionet' || networkId === 'genlayerBradbury' ||
        networkId === 'studionet' || networkId === 'bradbury') return 'GENLAYER';
    var n = networks();
    if (n && typeof n.getFamily === 'function') {
      var f = n.getFamily(networkId);
      if (f && f !== 'UNKNOWN') return f;
    }
    if (networkId) return 'EVM';
    return 'UNKNOWN';
  }

  function isGenLayerNetwork(networkId) { return networkFamily(networkId) === 'GENLAYER'; }

  // Resolve a contract address to its GenLayer network when it is a *known*
  // GenLayer contract (Studionet AuditAI or the Bradbury contract). Never
  // assumes an EVM network for an intelligent contract.
  function networkForContract(address) {
    var client = (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIGenLayerClient;
    if (!client || typeof client.knownContractFor !== 'function') return null;
    var known = client.knownContractFor(address);
    if (!known) return null;
    return { family: 'GENLAYER', networkId: known.networkId, chainId: known.chainId, known: known };
  }

  // Map free text (Chat) or a quick-action label to a real intent.
  // `hasAddress` true when a 0x… address was already detected in the message.
  function detectIntent(text, hasAddress) {
    var t = String(text || '').toLowerCase();
    if (hasAddress) return INTENTS.AUDIT_CONTRACT;
    if (/\b(create|make|generate|build)\b/.test(t) && /\b(contract|token|nft|erc|escrow|stak|vest|treasury|timelock|intelligent|vault)\b/.test(t)) return INTENTS.CREATE_CONTRACT;
    if (/safe.*approve|approve.*safe|is it safe|should i approve/i.test(t)) return INTENTS.ASSESS_APPROVAL;
    if (/approv|allowance/i.test(t)) return INTENTS.CHECK_APPROVALS;
    if (/portfolio|my wallet|my contracts|my tokens/i.test(t)) return INTENTS.VIEW_PORTFOLIO;
    if (/explain|what.*finding|findings|last finding/i.test(t)) return INTENTS.EXPLAIN_FINDINGS;
    if (/\b(interact|call|write to|execute)\b/.test(t) && /\b(contract|function|method)\b/.test(t)) return INTENTS.INTERACT_CONTRACT;
    if (/\b(read|show|list|inspect|view)\b/.test(t) && /\b(functions?|schemas?|methods?|contract)\b/.test(t)) return INTENTS.INSPECT_CONTRACT;
    if (/\baudit\b|\bscan\b|\binspect\b|0x[0-9a-f]{40}/i.test(t)) return INTENTS.AUDIT_CONTRACT;
    return 'UNKNOWN';
  }

  // Capability matrix — honest about wallet/read/write/network support.
  function capability(intent) {
    switch (intent) {
      case INTENTS.AUDIT_CONTRACT:
        return { wallet: false, read: true, write: false, evm: true, genlayer: true };
      case INTENTS.CREATE_CONTRACT:
        return { wallet: false, read: true, write: false, evm: true, genlayer: true }; // deploy (separate step) needs wallet
      case INTENTS.VIEW_PORTFOLIO:
        return { wallet: 'conditional', read: true, write: false, evm: true, genlayer: 'as-applicable' };
      case INTENTS.CHECK_APPROVALS:
        return { wallet: 'conditional', read: true, write: false, evm: true, genlayer: 'as-applicable' };
      case INTENTS.EXPLAIN_FINDINGS:
        return { wallet: false, read: true, write: false, evm: true, genlayer: true };
      case INTENTS.ASSESS_APPROVAL:
        return { wallet: 'conditional', read: true, write: false, evm: true, genlayer: 'as-applicable' };
      case INTENTS.INSPECT_CONTRACT:
        return { wallet: false, read: true, write: false, evm: true, genlayer: true };
      case INTENTS.INTERACT_CONTRACT:
        // Reads need no wallet; the write path is a separate, explicitly
        // confirmed step (never auto-signed), so the intent itself never writes.
        return { wallet: 'conditional', read: true, write: false, evm: false, genlayer: true };
      default:
        return { wallet: false, read: false, write: false, evm: false, genlayer: false };
    }
  }

  // Assemble the shared context from existing app state. Unknown fields stay null.
  function buildContext(state) {
    state = state || {};
    return {
      wallet: {
        connected: !!state.walletAddress,
        address: state.walletAddress || null,
        chainId: state.walletChainId || null
      },
      network: {
        audit: state.auditNetworkId || 'auto',
        transaction: 'studionet',
        deployment: 'studionet'
      },
      currentIntent: state.currentIntent || null,
      lastAudit: state.lastAuditResult || null,
      lastAuditAddress: state.lastAuditAddress || null,
      lastAuditChain: state.lastAuditChain || null,
      lastDeployment: state.lastDeployment || null,
      lastCreatedContract: state.pendingBuild || null,
      lastFindings: (state.lastAuditResult && state.lastAuditResult.findings) || null,
      lastApprovalContext: state.lastApprovalContext || null,
      lastPortfolio: state.lastPortfolio || null
    };
  }

  // Decide HOW to audit an address given the current context. This is the
  // critical routing: a GenLayer deployment is NEVER routed through EVM
  // eth_getCode discovery (which returns 0x for intelligent contracts).
  function planAudit(ctx) {
    var d = ctx && ctx.lastDeployment;
    if (d && d.address) {
      if (isGenLayerNetwork(d.network) || isGenLayerNetwork(d.networkId)) {
        return { mode: 'genlayer', address: d.address, deployment: d };
      }
      return { mode: 'evm', address: d.address, deployment: d };
    }
    if (ctx && ctx.lastAuditAddress) {
      return { mode: 'discover', address: ctx.lastAuditAddress, deployment: null };
    }
    return { mode: 'needs_input', address: null, deployment: null };
  }

  // Next-best-action suggestions based only on what is actually available.
  function nextActions(ctx) {
    var actions = [];
    if (ctx.lastDeployment && ctx.lastDeployment.address) {
      actions.push({ id: 'audit_contract', label: 'Audit Contract' });
      actions.push({ id: 'inspect_contract', label: 'Inspect Contract' });
      actions.push({ id: 'view_contract', label: 'View Contract' });
      if (ctx.lastDeployment.txHash) actions.push({ id: 'view_tx', label: 'View Transaction' });
      actions.push({ id: 'interact_contract', label: 'Interact with Contract' });
    } else if (ctx.lastAudit) {
      actions.push({ id: 'explain_findings', label: 'Explain Findings' });
      actions.push({ id: 'audit_again', label: 'Audit Again' });
    } else if (ctx.lastCreatedContract && ctx.lastCreatedContract.source) {
      actions.push({ id: 'copy_solidity', label: 'Copy Solidity' });
      actions.push({ id: 'create_genlayer', label: 'Create GenLayer Contract' });
    }
    return actions;
  }

  return {
    INTENTS: INTENTS,
    detectIntent: detectIntent,
    networkFamily: networkFamily,
    isGenLayerNetwork: isGenLayerNetwork,
    networkForContract: networkForContract,
    capability: capability,
    buildContext: buildContext,
    planAudit: planAudit,
    nextActions: nextActions
  };
});
