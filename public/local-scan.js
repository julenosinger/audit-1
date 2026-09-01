// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — local scan compatibility layer
//
// Thin wrapper over the Local Audit Engine (public/audit-engine.js). Keeps the
// existing `window.AuditAILocalScan` surface used by index.html while delegating
// the actual analysis to the engine.
//
//   scan(...)          → AuditEngine.auditContract(...) mapped to the flat shape
//   scanPortfolio(...) → deterministic curated-list scan via the engine
//   checkApprovals(...)→ real ERC-20 allowance checks (ethers, unchanged)
//   glossary(...)      → static glossary (unchanged)
// ═══════════════════════════════════════════════════════════════════════════════
(function () {
  'use strict';

  function engine() {
    return window.AuditEngine || (typeof globalThis !== 'undefined' && globalThis.AuditEngine);
  }

  function flatMap(address, result) {
    var risk = result.risk || { score: 100, level: 'LIMITED ANALYSIS', confidence: 'LOW' };
    var tags = [];
    if (result.contract && result.contract.type && result.contract.type !== 'Unknown') tags.push(result.contract.type);
    if (result.capabilities) {
      if (result.capabilities.proxy && result.capabilities.proxy.detected) tags.push('Proxy');
      if (result.capabilities.ownership === 'Detected') tags.push('Ownable');
      if (result.capabilities.mint && result.capabilities.mint.present) tags.push('Mintable');
      if (result.capabilities.pause === 'Detected') tags.push('Pausable');
    }
    tags.push('Local scan');

    return {
      score: risk.score,
      verdict: risk.level,
      level: risk.level,
      confidence: risk.confidence,
      findings: result.findings || [],
      summary: result.summary || '',
      analysis: result.summary || '',
      tags: tags,
      category: (result.contract && result.contract.type) || 'Unknown',
      context: result.context || '',
      risk: risk,
      contract: result.contract,
      capabilities: result.capabilities,
      completeness: result.analysis && result.analysis.completeness,
      bytecodeHash: result.bytecodeHash,
      analysisVersion: result.analysisVersion,
      payload: result.payload || null,
      evidenceGraph: result.evidenceGraph || null,
      privilegedOperations: result.privilegedOperations || [],
      accessControlSummary: result.accessControlSummary || null,
      privilegeGraph: result.privilegeGraph || null
    };
  }

  async function scan(opts) {
    opts = opts || {};
    var eng = engine();
    if (!eng) throw new Error('Local Audit Engine not loaded');
    var result = await eng.auditContract(opts);
    return flatMap(opts.address, result);
  }

  // ── Portfolio: deterministic scan of a curated popular-contracts list ──────
  var POPULAR = [
    { address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', name: 'USDC' },
    { address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', name: 'WETH' },
    { address: '0x6B175474E89094C44Da98b954EedeAC495271d0F', name: 'DAI' },
    { address: '0xE592427A0AEce92De3Edee1F18E0157C05861564', name: 'Uniswap V3 Router' },
    { address: '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2', name: 'Aave V3 Pool' },
    { address: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', name: 'Uniswap V2 Router' }
  ];

  async function scanPortfolio(opts) {
    opts = opts || {};
    var provider = opts.provider || null;
    var chainName = opts.chainName || 'Ethereum';
    var out = [];
    for (var i = 0; i < POPULAR.length; i++) {
      var p = POPULAR[i];
      var r = await scan({ address: p.address, provider: provider });
      out.push({ address: p.address, name: p.name, chain: chainName, score: r.score, verdict: r.verdict });
    }
    return out;
  }

  // ── Approvals: real ERC-20 allowance checks against known spenders ─────────
  var UNI_ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
  var ONEINCH = '0x1111111254EEB25477B68fb85Ed929f73A960582';
  var TOKEN_CHECKS = [
    { token: 'USDC', addr: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', spender: UNI_ROUTER, spenderName: 'Uniswap V2 Router' },
    { token: 'USDT', addr: '0xdAC17F958D2ee523a2206206994597C13D831ec7', spender: UNI_ROUTER, spenderName: 'Uniswap V2 Router' },
    { token: 'DAI', addr: '0x6B175474E89094C44Da98b954EedeAC495271d0F', spender: ONEINCH, spenderName: '1inch Router' },
    { token: 'WETH', addr: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', spender: ONEINCH, spenderName: '1inch Router' }
  ];

  var ERC20_ABI = ['function allowance(address owner, address spender) view returns (uint256)'];
  var MAX_UINT = '115792089237316195423570985008687907853269984665640564039457584007913129639935';

  async function checkApprovals(opts) {
    opts = opts || {};
    var provider = opts.provider || null;
    var wallet = opts.wallet;
    var out = [];
    for (var i = 0; i < TOKEN_CHECKS.length; i++) {
      var t = TOKEN_CHECKS[i];
      var amount = '0';
      try {
        var c = new ethers.Contract(t.addr, ERC20_ABI, provider);
        var al = await c.allowance(wallet, t.spender);
        amount = al.toString();
      } catch (e) { amount = '0'; }

      var risk;
      if (amount === MAX_UINT) { risk = 'HIGH'; amount = 'unlimited'; }
      else if (amount !== '0') { risk = 'MEDIUM'; }
      else { risk = 'NONE'; }

      out.push({ token: t.token, spender: t.spender, spenderName: t.spenderName, amount: amount, risk: risk });
    }
    return out;
  }

  // ── Static glossary for free-form questions (no API) ──────────────────────
  var GLOSSARY = {
    reentrancy: '**Reentrancy** is when a contract makes an external call before updating its state, letting a malicious callee re-enter and drain funds. Mitigate with checks-effects-interactions and reentrancy guards.',
    approval: 'An **approval** lets a spender move a specific amount of your token. Unlimited approvals are risky — revoke anything you no longer use.',
    allowance: '**Allowance** is the maximum amount a spender can transfer on your behalf. Prefer a specific amount over unlimited.',
    delegatecall: '**DELEGATECALL** runs another contract\u2019s code in your storage context — the basis of proxies, but dangerous if the implementation is compromised.',
    selfdestruct: '**SELFDESTRUCT** removes a contract\u2019s code and can send its balance to another address.',
    proxy: 'A **proxy** forwards calls to an implementation via DELEGATECALL. Always verify the implementation address and upgradeability controls.',
    honeypot: 'A **honeypot** lets users buy a token but blocks selling. Check transfer/sell logic before trading.',
    flashloan: 'A **flash loan** borrows and repays within one transaction. Not an exploit by itself, but used to attack under-collateralized logic.'
  };

  function glossary(query) {
    var q = (query || '').toLowerCase();
    var keys = Object.keys(GLOSSARY);
    for (var i = 0; i < keys.length; i++) {
      if (q.indexOf(keys[i]) !== -1) return GLOSSARY[keys[i]];
    }
    return null;
  }

  window.AuditAILocalScan = {
    scan: scan,
    scanPortfolio: scanPortfolio,
    checkApprovals: checkApprovals,
    glossary: glossary
  };
})();
