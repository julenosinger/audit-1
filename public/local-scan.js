// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — local EVM scanner (zero LLM, ethers.js only)
//
// Deterministic heuristics over on-chain bytecode. No paid API, no LLM.
// Output is stable and safe to publish on-chain via the GenLayer contract.
//
// Entry: { address, provider?, bytecode? } → result
//   { score, verdict, findings, summary, tags, category, analysis, context }
//
// IMPORTANT: opcode detection here is a HEURISTIC. Single-byte opcodes are
// matched as hex substrings, which can also appear inside PUSH data. Findings
// are therefore indicators, never proof.
// ═══════════════════════════════════════════════════════════════════════════════
(function () {
  'use strict';

  var SEV_WEIGHT = { HIGH: 25, MEDIUM: 12, LOW: 5, INFO: 0 };

  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

  function verdictFor(score) {
    return score >= 80 ? 'SAFE' : score >= 50 ? 'WARNING' : 'DANGER';
  }

  function shortAddr(a) {
    return a ? a.slice(0, 10) + '\u2026' + a.slice(-6) : '';
  }

  function analyzeCode(address, code) {
    var findings = [];
    var tags = [];

    var isEOA = !code || code === '0x' || code === '0x0';
    if (isEOA) {
      findings.push({
        severity: 'INFO',
        title: 'Not a contract (EOA)',
        description: 'No runtime bytecode at this address — it is an externally-owned account (EOA), not a deployed smart contract.'
      });
      tags.push('EOA');
      return { score: 50, findings: findings, tags: tags, category: 'EOA' };
    }

    var body = (code.slice(0, 2) === '0x') ? code.slice(2).toLowerCase() : code.toLowerCase();
    var byteLen = body.length / 2;

    if (byteLen < 20) {
      findings.push({ severity: 'MEDIUM', title: 'Minimal bytecode', description: 'Runtime code is extremely small (' + Math.round(byteLen) + ' bytes) — possibly a stub or minimal proxy.' });
    } else if (byteLen < 200) {
      findings.push({ severity: 'LOW', title: 'Small bytecode', description: 'Runtime code is small (' + Math.round(byteLen) + ' bytes).' });
    } else {
      tags.push('Contract');
    }

    // Heuristic opcode substrings (see header note).
    if (body.indexOf('f2') !== -1) {
      findings.push({ severity: 'HIGH', title: 'CALLCODE opcode present', description: 'Legacy CALLCODE (0xf2) detected — associated with older delegate-style calls.' });
    }
    if (body.indexOf('ff') !== -1) {
      findings.push({ severity: 'MEDIUM', title: 'SELFDESTRUCT opcode present', description: 'SELFDESTRUCT (0xff) detected — the contract can destroy itself and move its balance.' });
    }
    if (body.indexOf('f4') !== -1) {
      findings.push({ severity: 'LOW', title: 'DELEGATECALL opcode present', description: 'DELEGATECALL (0xf4) detected — common in proxies; verify the implementation address and upgrade controls.' });
    }

    if (findings.length === 0) {
      findings.push({ severity: 'INFO', title: 'No obvious dangerous opcodes', description: 'A quick static scan found no CALLCODE / SELFDESTRUCT / DELEGATECALL patterns.' });
    }

    var score = 100;
    findings.forEach(function (f) { score -= SEV_WEIGHT[f.severity] || 0; });
    score = clamp(score, 0, 100);

    return { score: score, findings: findings, tags: tags, category: 'Unknown' };
  }

  function summarize(address, score, verdict, findings) {
    var high = findings.filter(function (f) { return f.severity === 'HIGH'; }).length;
    var med = findings.filter(function (f) { return f.severity === 'MEDIUM'; }).length;
    var low = findings.filter(function (f) { return f.severity === 'LOW'; }).length;

    var s = 'Static local scan of ' + shortAddr(address) + ' scored ' + score + '/100 (' + verdict + ').';
    if (high + med + low === 0) {
      s += ' No high-risk bytecode patterns detected in a quick heuristic pass.';
    } else {
      s += ' Found ' + high + ' high, ' + med + ' medium, ' + low + ' low severity heuristic(s).';
    }
    s += ' This is a deterministic local result — no LLM involved.';
    return s;
  }

  function buildContext(address, code, findings) {
    var snippet = code ? (code.length > 8000 ? code.slice(0, 8000) : code) : '(no bytecode)';
    var lines = findings.map(function (f) { return f.severity + ': ' + f.title; }).join('; ');
    return 'Contract: ' + address + '\nBytecode (truncated): ' + snippet + '\nLocal findings: ' + (lines || 'none');
  }

  async function scan(opts) {
    opts = opts || {};
    var address = opts.address;
    var provider = opts.provider || null;
    var code = opts.bytecode || null;

    if (!code && provider) {
      try { code = await provider.getCode(address); } catch (e) { code = null; }
    }

    var r = analyzeCode(address, code);
    var score = r.score;
    var verdict = verdictFor(score);
    var summary = summarize(address, score, verdict, r.findings);
    var context = buildContext(address, code, r.findings);

    return {
      score: score,
      verdict: verdict,
      findings: r.findings,
      summary: summary,
      analysis: summary,
      tags: r.tags,
      category: r.category,
      context: context
    };
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
