// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Local Audit Engine (deterministic, zero LLM)
//
// A technically honest static analyzer for EVM bytecode:
//
//   bytecode → EVM Disassembler → Instruction List → Static Analyzer → Risk Engine
//
// It NEVER claims a contract is "SAFE" merely because no rule fired, and NEVER
// reports a vulnerability from a weak heuristic alone. Findings carry severity,
// confidence, evidence, and a recommendation, and observed facts are kept
// separate from inferences and unknowns.
//
// No external AI/API. `auditContract` only needs a bytecode string (optionally
// fetched via an ethers provider passed in). Works identically in browser and
// Node (for tests).
//
// LIMITATIONS (important): this is a *linear* static disassembler — it decodes
// bytes sequentially from offset 0 and does NOT perform control-flow analysis.
// Bytes in unreachable regions, jump tables, or embedded data may therefore be
// decoded as opcodes (a known, fundamental limit of linear EVM disassembly).
// Findings reflect what is *observed in the linear stream*, carry a confidence
// level, and never assert a vulnerability is confirmed. ABI-based findings are
// only produced when an ABI is supplied.
//
// Public API (window.AuditEngine):
//   disassemble(bytecode)            -> { valid, error, instructions[] }
//   analyze(bytecode, opts)          -> full standardized result (sync)
//   auditContract(opts)              -> Promise<result> (fetches bytecode)
//   getFindings(result?), getRisk(result?), getContractInfo(result?)
//   explainFinding(finding)          -> human-readable markdown
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditEngine = api;
})(function () {
  'use strict';

  var VERSION = '2.0.0';

  // ── 1. EVM opcode table ────────────────────────────────────────────────────
  // name -> { byte, imm } where imm is the number of immediate data bytes.
  // Only PUSH1..PUSH32 carry immediate data; every other opcode is 1 byte.
  var OPCODES = (function () {
    var t = {};
    function set(hex, name, imm) { t[hex] = { name: name, imm: imm || 0 }; }

    // Arithmetic / bitwise
    set('00', 'STOP'); set('01', 'ADD'); set('02', 'MUL'); set('03', 'SUB');
    set('04', 'DIV'); set('05', 'SDIV'); set('06', 'MOD'); set('07', 'SMOD');
    set('08', 'ADDMOD'); set('09', 'MULMOD'); set('0a', 'EXP'); set('0b', 'SIGNEXTEND');
    set('10', 'LT'); set('11', 'GT'); set('12', 'SLT'); set('13', 'SGT');
    set('14', 'EQ'); set('15', 'ISZERO'); set('16', 'AND'); set('17', 'OR');
    set('18', 'XOR'); set('19', 'NOT'); set('1a', 'BYTE'); set('1b', 'SHL');
    set('1c', 'SHR'); set('1d', 'SAR');
    // Env / info
    set('20', 'KECCAK256'); set('30', 'ADDRESS'); set('31', 'BALANCE');
    set('32', 'ORIGIN'); set('33', 'CALLER'); set('34', 'CALLVALUE');
    set('35', 'CALLDATALOAD'); set('36', 'CALLDATASIZE'); set('37', 'CALLDATACOPY');
    set('38', 'CODESIZE'); set('39', 'CODECOPY'); set('3a', 'GASPRICE');
    set('3b', 'EXTCODESIZE'); set('3c', 'EXTCODECOPY'); set('3d', 'RETURNDATASIZE');
    set('3e', 'RETURNDATACOPY'); set('3f', 'EXTCODEHASH');
    set('40', 'BLOCKHASH'); set('41', 'COINBASE'); set('42', 'TIMESTAMP');
    set('43', 'NUMBER'); set('44', 'PREVRANDAO'); set('45', 'GASLIMIT');
    set('46', 'CHAINID'); set('47', 'SELFBALANCE'); set('48', 'BASEFEE');
    set('4a', 'BLOBBASEFEE');
    // Memory / storage / flow
    set('50', 'POP'); set('51', 'MLOAD'); set('52', 'MSTORE'); set('53', 'MSTORE8');
    set('54', 'SLOAD'); set('55', 'SSTORE'); set('56', 'JUMP'); set('57', 'JUMPI');
    set('58', 'PC'); set('59', 'MSIZE'); set('5a', 'GAS'); set('5b', 'JUMPDEST');
    set('5c', 'TLOAD'); set('5d', 'TSTORE'); set('5e', 'MCOPY'); set('5f', 'PUSH0');
    // System
    set('a0', 'LOG0'); set('a1', 'LOG1'); set('a2', 'LOG2'); set('a3', 'LOG3'); set('a4', 'LOG4');
    set('f0', 'CREATE'); set('f1', 'CALL'); set('f2', 'CALLCODE'); set('f3', 'RETURN');
    set('f4', 'DELEGATECALL'); set('f5', 'CREATE2'); set('fa', 'STATICCALL');
    set('fd', 'REVERT'); set('fe', 'INVALID'); set('ff', 'SELFDESTRUCT');
    // PUSH1..PUSH32 (0x60..0x7f)
    for (var p = 1; p <= 32; p++) { set((0x5f + p).toString(16), 'PUSH' + p, p); }
    // DUP1..DUP16 (0x80..0x8f), SWAP1..SWAP16 (0x90..0x9f)
    for (var d = 1; d <= 16; d++) { set((0x7f + d).toString(16), 'DUP' + d); }
    for (var s = 1; s <= 16; s++) { set((0x8f + s).toString(16), 'SWAP' + s); }
    return t;
  })();

  // ── 2. Disassembler ────────────────────────────────────────────────────────
  function normalizeHex(code) {
    if (code === null || code === undefined) return '';
    var s = String(code).trim();
    if (s.slice(0, 2) === '0x' || s.slice(0, 2) === '0X') s = s.slice(2);
    s = s.toLowerCase();
    if (!/^[0-9a-f]*$/.test(s)) return null; // invalid hex
    if (s.length % 2 !== 0) s = '0' + s;
    return s;
  }

  function disassemble(bytecode) {
    var hex = normalizeHex(bytecode);
    if (hex === null) {
      return { valid: false, error: 'Invalid hexadecimal bytecode', instructions: [] };
    }
    var instructions = [];
    var i = 0, pc = 0;
    while (i < hex.length) {
      var b = hex.substr(i, 2);
      var op = OPCODES[b];
      if (!op) {
        instructions.push({ pc: pc, opcode: 'INVALID', byte: b, argument: '' });
        i += 2; pc += 1;
        continue;
      }
      var imm = op.imm || 0;
      var arg = '';
      if (imm > 0) {
        arg = hex.substr(i + 2, imm * 2); // may be short if truncated at EOF
        i += 2 + imm * 2;
      } else {
        i += 2;
      }
      instructions.push({ pc: pc, opcode: op.name, byte: b, argument: arg });
      pc += 1 + imm;
    }
    return { valid: true, error: null, instructions: instructions };
  }

  // ── 3. Finding engine ──────────────────────────────────────────────────────
  var SEVERITY_WEIGHT = { CRITICAL: 60, HIGH: 25, MEDIUM: 12, LOW: 5, INFO: 0 };
  var CONFIDENCE_MULT = { HIGH: 1.0, MEDIUM: 0.7, LOW: 0.4 };

  function scoreImpact(severity, confidence, exploitability) {
    var w = SEVERITY_WEIGHT[severity] || 0;
    var c = CONFIDENCE_MULT[confidence] || 0.4;
    var e = (exploitability === undefined) ? 1.0 : exploitability;
    return Math.round(w * c * e * 10) / 10;
  }

  var _seq = 0;
  function createFinding(cfg) {
    _seq += 1;
    var id = cfg.id || (cfg.category + '-' + _seq);
    var sev = cfg.severity || 'INFO';
    var conf = cfg.confidence || 'LOW';
    return {
      id: id,
      category: cfg.category,
      severity: sev,
      confidence: conf,
      title: cfg.title,
      description: cfg.description || '',
      evidence: cfg.evidence || [],
      recommendation: cfg.recommendation || '',
      scoreImpact: (cfg.scoreImpact === undefined) ? scoreImpact(sev, conf, cfg.exploitability) : cfg.scoreImpact,
      source: cfg.source || 'OBSERVED'
    };
  }

  // ── 4. Risk engine ─────────────────────────────────────────────────────────
  var LEVEL_RANK = {
    'LIMITED ANALYSIS': 0,
    'LOW RISK': 1,
    'MODERATE RISK': 2,
    'HIGH RISK': 3,
    'CRITICAL RISK': 4
  };

  function levelFromScore(score) {
    if (score >= 85) return 'LOW RISK';
    if (score >= 70) return 'MODERATE RISK';
    if (score >= 45) return 'HIGH RISK';
    return 'CRITICAL RISK';
  }

  function levelFromSeverity(severity) {
    if (severity === 'CRITICAL') return 'CRITICAL RISK';
    if (severity === 'HIGH') return 'HIGH RISK';
    if (severity === 'MEDIUM') return 'MODERATE RISK';
    return 'LOW RISK';
  }

  function assessRisk(findings, completeness) {
    var score = 100;
    findings.forEach(function (f) { score -= f.scoreImpact || 0; });
    score = Math.max(0, Math.min(100, Math.round(score)));

    var level = levelFromScore(score);
    findings.forEach(function (f) {
      if (f.confidence === 'LOW') return; // weak evidence does not escalate the level
      var l = levelFromSeverity(f.severity);
      if (LEVEL_RANK[l] > LEVEL_RANK[level]) level = l;
    });

    var confidence = completeness === 'full' ? 'HIGH' : completeness === 'partial' ? 'MEDIUM' : 'LOW';
    return { score: score, level: level, confidence: confidence };
  }

  // ── 5. Known 4-byte selectors & EIP-1967 slots ────────────────────────────
  var ERC20_SELECTORS = {
    transfer: 'a9059cbb', transferFrom: '23b872dd', approve: '095ea7b3',
    allowance: 'dd62ed3e', balanceOf: '70a08231', totalSupply: '18160ddd',
    name: '06fdde03', symbol: '95d89b41', decimals: '313ce567'
  };
  var ERC721_SELECTORS = {
    balanceOf: '70a08231', ownerOf: '6352211e', approve: '095ea7b3',
    getApproved: '081812fc', setApprovalForAll: 'a22cb465', isApprovedForAll: 'e985e9c5',
    transferFrom: '23b872dd', safeTransferFrom3: '42842e0e', safeTransferFrom4: 'b88d4fde',
    tokenURI: 'c87b56dd', supportsInterface: '01ffc9a7'
  };
  var ERC1155_SELECTORS = {
    balanceOf: '00fdd58e', balanceOfBatch: '4e1273f4', setApprovalForAll: 'a22cb465',
    isApprovedForAll: 'e985e9c5', safeTransferFrom: 'f242432a',
    safeBatchTransferFrom: '2eb2c2d6', uri: '0e89341c', supportsInterface: '01ffc9a7'
  };
  var OWNABLE_SELECTORS = { owner: '8da5cb5b', transferOwnership: 'f2fde38b', renounceOwnership: '715018a6' };
  var ACCESS_CONTROL_SELECTORS = {
    hasRole: '91d14854', getRoleAdmin: '248a9ca3', grantRole: '2f2ff15d',
    revokeRole: 'd547741f', renounceRole: '36568abe'
  };
  var PAUSE_SELECTORS = { pause: '8456cb59', unpause: '3f4ba83a' };
  var MINT_SELECTORS = [
    { label: 'mint(address,uint256)', sel: '40c10f19' },
    { label: 'mint(uint256)', sel: 'a0712d68' },
    { label: 'mintTo(address,uint256)', sel: '449a52f8' },
    { label: 'mint(address,uint256) alt', sel: '156e29f6' }
  ];
  var BURN_SELECTORS = { 'burn(uint256)': '42966c68', 'burnFrom(address,uint256)': '79cc6790' };

  var EIP1967_SLOTS = {
    implementation: '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    admin: 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
    beacon: 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
  };

  // ── 6. Rules ───────────────────────────────────────────────────────────────

  function collectSelectors(instructions) {
    var selectors = {}; // selector -> true
    var push32 = [];    // array of 32-byte hex strings
    var push20 = [];    // array of 20-byte hex strings
    instructions.forEach(function (ins) {
      if (ins.opcode === 'PUSH4' && ins.argument.length === 8) selectors[ins.argument] = true;
      else if (ins.opcode === 'PUSH32' && ins.argument.length === 64) push32.push(ins.argument);
      else if (ins.opcode === 'PUSH20' && ins.argument.length === 40) push20.push(ins.argument);
    });
    return { selectors: selectors, push32: push32, push20: push20 };
  }

  function hasAny(selectors, table) {
    var keys = Object.keys(table);
    for (var i = 0; i < keys.length; i++) {
      if (selectors[table[keys[i]]]) return true;
    }
    return false;
  }

  function countHits(selectors, table) {
    var n = 0, keys = Object.keys(table);
    for (var i = 0; i < keys.length; i++) { if (selectors[table[keys[i]]]) n++; }
    return n;
  }

  function abiFnNames(abi) {
    var out = {};
    if (!Array.isArray(abi)) return out;
    abi.forEach(function (item) {
      if (item && item.type === 'function' && item.name) out[item.name] = true;
    });
    return out;
  }

  function hasAbiFn(abi, pattern) {
    var names = abiFnNames(abi);
    return Object.keys(names).some(function (n) { return pattern.test(n); });
  }

  function ruleBytecodeSize(ctx) {
    var size = ctx.bodyLen;
    if (size === 0) {
      ctx.findings.push(createFinding({
        id: 'bytecode-empty', category: 'bytecode', severity: 'INFO', confidence: 'HIGH',
        title: 'No runtime bytecode (EOA)',
        description: 'No code exists at this address — it is an externally-owned account (EOA), not a deployed smart contract.',
        evidence: [{ kind: 'OBSERVED', text: 'getCode returned 0x' }],
        recommendation: 'Verify you are auditing a contract address, not a wallet.'
      }));
    } else if (size < 20) {
      ctx.findings.push(createFinding({
        id: 'bytecode-minimal', category: 'bytecode', severity: 'LOW', confidence: 'HIGH', exploitability: 0.3,
        title: 'Minimal runtime bytecode',
        description: 'Runtime code is extremely small (' + size + ' bytes) — possibly a stub, factory child, or minimal proxy.',
        evidence: [{ kind: 'OBSERVED', text: 'bytecode size = ' + size + ' bytes' }],
        recommendation: 'Confirm this is the intended runtime and not a stale/partial deployment.'
      }));
    } else if (size < 200) {
      ctx.findings.push(createFinding({
        id: 'bytecode-small', category: 'bytecode', severity: 'INFO', confidence: 'HIGH', exploitability: 0.2,
        title: 'Small runtime bytecode',
        description: 'Runtime code is small (' + size + ' bytes).',
        evidence: [{ kind: 'OBSERVED', text: 'bytecode size = ' + size + ' bytes' }],
        recommendation: 'None — informational only.'
      }));
    }
  }

  function ruleExternalCalls(ctx) {
    var c = ctx.ops;
    if (c.CALLCODE.length) {
      ctx.findings.push(createFinding({
        id: 'external-call-callcode', category: 'external-call', severity: 'MEDIUM', confidence: 'HIGH', exploitability: 0.7,
        title: 'CALLCODE opcode used',
        description: 'Legacy CALLCODE was observed at PC ' + c.CALLCODE.join(', ') + '. CALLCODE executes the callee\u2019s code in the caller\u2019s context (msg.sender preserved), which is error-prone.',
        evidence: c.CALLCODE.map(function (pc) { return { kind: 'OBSERVED', text: 'CALLCODE at PC ' + pc }; }),
        recommendation: 'Prefer CALL or DELEGATECALL with explicit, audited semantics.'
      }));
    }
    if (c.CALL.length || c.STATICCALL.length || c.DELEGATECALL.length) {
      var kinds = [];
      if (c.CALL.length) kinds.push(c.CALL.length + 'x CALL');
      if (c.STATICCALL.length) kinds.push(c.STATICCALL.length + 'x STATICCALL');
      if (c.DELEGATECALL.length) kinds.push(c.DELEGATECALL.length + 'x DELEGATECALL');
      ctx.findings.push(createFinding({
        id: 'external-call-present', category: 'external-call', severity: 'INFO', confidence: 'HIGH', exploitability: 0.2,
        title: 'External calls present',
        description: 'The contract performs external calls (' + kinds.join(', ') + '). This is normal; it is NOT evidence of reentrancy on its own.',
        evidence: [{ kind: 'OBSERVED', text: kinds.join(', ') }],
        recommendation: 'If state changes follow external calls, review ordering (checks-effects-interactions) for reentrancy.'
      }));
      if (c.SSTORE > 0 && (c.CALL.length || c.DELEGATECALL.length)) {
        ctx.findings.push(createFinding({
          id: 'reentrancy-potential', category: 'reentrancy', severity: 'LOW', confidence: 'LOW', exploitability: 0.4,
          title: 'Potential external-call risk',
          description: 'The contract both writes state (SSTORE) and makes external calls. Whether this is exploitable reentrancy depends on call ordering and data flow, which static bytecode analysis cannot prove.',
          evidence: [
            { kind: 'OBSERVED', text: 'SSTORE present (' + c.SSTORE + 'x)' },
            { kind: 'OBSERVED', text: 'external CALL/DELEGATECALL present' },
            { kind: 'UNKNOWN', text: 'call ordering relative to state updates' }
          ],
          recommendation: 'Review with a data-flow analyzer or audit the source. This is a potential, not confirmed, risk.'
        }));
      }
    }
  }

  function ruleSelfdestruct(ctx) {
    if (ctx.ops.SELFDESTRUCT.length) {
      ctx.findings.push(createFinding({
        id: 'selfdestruct-present', category: 'selfdestruct', severity: 'MEDIUM', confidence: 'HIGH', exploitability: 0.8,
        title: 'SELFDESTRUCT opcode used',
        description: 'SELFDESTRUCT was observed at PC ' + ctx.ops.SELFDESTRUCT.join(', ') + '. The contract can destroy its own code and move its balance.',
        evidence: ctx.ops.SELFDESTRUCT.map(function (pc) { return { kind: 'OBSERVED', text: 'SELFDESTRUCT at PC ' + pc }; }),
        recommendation: 'Verify who can trigger it and whether funds can be unexpectedly removed.'
      }));
    }
  }

  function ruleTxOrigin(ctx) {
    if (ctx.ops.ORIGIN.length) {
      ctx.findings.push(createFinding({
        id: 'tx-origin-usage', category: 'tx-origin', severity: 'MEDIUM', confidence: 'MEDIUM', exploitability: 0.8,
        title: 'tx.origin usage detected',
        description: 'The ORIGIN opcode (tx.origin) was observed at PC ' + ctx.ops.ORIGIN.join(', ') + '. Using tx.origin for authorization can be phished via malicious contracts. The actual risk depends on how the value is used, which static analysis cannot fully determine.',
        evidence: ctx.ops.ORIGIN.map(function (pc) { return { kind: 'OBSERVED', text: 'ORIGIN at PC ' + pc }; }),
        recommendation: 'Prefer msg.sender for authorization. If tx.origin is required, isolate it and audit its use.'
      }));
    }
  }

  function ruleStorage(ctx) {
    if (ctx.ops.SLOAD > 0 || ctx.ops.SSTORE > 0) {
      ctx.findings.push(createFinding({
        id: 'storage-usage', category: 'storage', severity: 'INFO', confidence: 'HIGH', exploitability: 0,
        title: 'Stateful contract',
        description: 'Uses persistent storage (SLOAD x' + ctx.ops.SLOAD + ', SSTORE x' + ctx.ops.SSTORE + ').',
        evidence: [{ kind: 'OBSERVED', text: 'SLOAD=' + ctx.ops.SLOAD + ' SSTORE=' + ctx.ops.SSTORE }],
        recommendation: 'None — informational.'
      }));
    }
  }

  function ruleProxy(ctx) {
    var d = ctx.ops.DELEGATECALL;
    var hasDel = d.length > 0;
    var impl = ctx.push32.indexOf(EIP1967_SLOTS.implementation) !== -1;
    var admin = ctx.push32.indexOf(EIP1967_SLOTS.admin) !== -1;
    var beacon = ctx.push32.indexOf(EIP1967_SLOTS.beacon) !== -1;

    var cap = ctx.capabilities.proxy;

    if (hasDel && (impl || admin || beacon)) {
      cap.detected = true; cap.confidence = 'HIGH';
      cap.upgradeable = (admin || beacon) ? 'Detected' : 'UNKNOWN';
      ctx.findings.push(createFinding({
        id: 'proxy-detected', category: 'proxy', severity: 'INFO', confidence: 'HIGH', exploitability: 0.3,
        title: 'Proxy pattern detected (EIP-1967)',
        description: 'DELEGATECALL plus an EIP-1967 slot constant (' + (impl ? 'implementation' : beacon ? 'beacon' : 'admin') + ') indicate an upgradeable proxy.',
        evidence: [
          { kind: 'OBSERVED', text: 'DELEGATECALL at PC ' + d.join(', ') },
          { kind: 'OBSERVED', text: 'EIP-1967 slot present' }
        ],
        recommendation: 'Verify the implementation address and upgrade/admin controls. Upgradability is a capability, not a vulnerability by itself.'
      }));
    } else if (hasDel) {
      cap.detected = true; cap.confidence = 'LOW';
      ctx.findings.push(createFinding({
        id: 'proxy-potential', category: 'proxy', severity: 'INFO', confidence: 'LOW', exploitability: 0.2,
        title: 'Potential proxy pattern',
        description: 'DELEGATECALL was observed, but no EIP-1967 slot was found — this is only a potential proxy, not confirmed.',
        evidence: [
          { kind: 'OBSERVED', text: 'DELEGATECALL at PC ' + d.join(', ') },
          { kind: 'UNKNOWN', text: 'implementation address not resolved' }
        ],
        recommendation: 'If this is a proxy, verify the implementation address manually.'
      }));
    }
    // Resolve a hard-coded implementation candidate from PUSH20 (INFERRED).
    var addrs = ctx.push20.filter(function (a) { return /^[0-9a-f]{40}$/.test(a) && a !== '0'.repeat(40); });
    if (hasDel && addrs.length && !impl) {
      cap.implementation = '0x' + addrs[0] + ' (inferred)';
    }
  }

  function ruleOwnership(ctx) {
    var s = ctx.selectors;
    var cap = ctx.capabilities.ownership;
    var ownerFn = !!s[OWNABLE_SELECTORS.owner];
    var transferFn = !!s[OWNABLE_SELECTORS.transferOwnership];
    var acHits = countHits(s, ACCESS_CONTROL_SELECTORS);

    if (ctx.abi) {
      var names = abiFnNames(ctx.abi);
      ownerFn = ownerFn || !!names['owner'];
      transferFn = transferFn || !!names['transferOwnership'];
      acHits = acHits || (hasAbiFn(ctx.abi, /grantRole|hasRole|renounceRole|revokeRole|getRoleAdmin/) ? 2 : 0);
    }

    if (ownerFn && transferFn) {
      cap = 'Detected';
      ctx.findings.push(createFinding({
        id: 'ownership-ownable', category: 'ownership', severity: 'INFO', confidence: 'HIGH', exploitability: 0.4,
        title: 'Ownable-style ownership detected',
        description: 'owner() and transferOwnership() selectors are present — the contract has a single privileged owner.',
        evidence: [
          { kind: 'OBSERVED', text: 'selector owner() = 0x' + OWNABLE_SELECTORS.owner },
          { kind: 'OBSERVED', text: 'selector transferOwnership() = 0x' + OWNABLE_SELECTORS.transferOwnership }
        ],
        recommendation: 'Verify what the owner can do (mint, fees, pause, upgrade). Privilege is not a flaw unless misused.'
      }));
    } else if (ownerFn) {
      cap = 'Potential';
      ctx.findings.push(createFinding({
        id: 'ownership-potential', category: 'ownership', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.3,
        title: 'Potential privileged owner',
        description: 'An owner() selector was detected, but transfer/renounce controls were not identified.',
        evidence: [{ kind: 'OBSERVED', text: 'selector owner() = 0x' + OWNABLE_SELECTORS.owner }],
        recommendation: 'Determine the owner\u2019s capabilities from the source/ABI.'
      }));
    } else {
      cap = 'Unknown';
    }

    if (acHits >= 2) {
      ctx.findings.push(createFinding({
        id: 'access-control-roles', category: 'access-control', severity: 'INFO', confidence: 'HIGH', exploitability: 0.3,
        title: 'Role-based access control (AccessControl)',
        description: 'Multiple role-management selectors (grantRole/hasRole/revokeRole) are present, suggesting AccessControl.',
        evidence: [{ kind: 'OBSERVED', text: acHits + ' AccessControl selectors detected' }],
        recommendation: 'Review role grants — the default admin role can grant any role.'
      }));
    }
  }

  function ruleToken(ctx) {
    var s = ctx.selectors;
    var type = 'Unknown';

    var erc1155 = (!!s[ERC1155_SELECTORS.safeTransferFrom] || !!s[ERC1155_SELECTORS.safeBatchTransferFrom]) &&
      (!!s[ERC1155_SELECTORS.balanceOf] || !!s[ERC1155_SELECTORS.isApprovedForAll]);
    var erc721 = (!!s[ERC721_SELECTORS.ownerOf] && !!s[ERC721_SELECTORS.balanceOf]) ||
      (!!s[ERC721_SELECTORS.safeTransferFrom3] && !!s[ERC721_SELECTORS.ownerOf]);
    var erc20Hits = countHits(s, ERC20_SELECTORS);

    if (erc1155) type = 'ERC-1155';
    else if (erc721 && !erc1155) type = 'ERC-721';
    else if (erc20Hits >= 4) type = 'ERC-20';

    ctx.contract.type = type;

    if (type !== 'Unknown') {
      ctx.findings.push(createFinding({
        id: 'token-standard', category: 'token', severity: 'INFO', confidence: type === 'ERC-20' ? 'HIGH' : 'MEDIUM', exploitability: 0.1,
        title: type + ' token detected',
        description: 'Function selectors are consistent with the ' + type + ' standard.',
        evidence: [{ kind: 'INFERRED', text: 'selector fingerprint matches ' + type }],
        recommendation: 'For tokens, review mint/burn/pause/fee/blacklist capabilities separately.'
      }));
    }
  }

  function ruleMintBurn(ctx) {
    var s = ctx.selectors;
    var mintSels = [], burnSels = [];
    MINT_SELECTORS.forEach(function (m) { if (s[m.sel]) mintSels.push(m.label); });
    Object.keys(BURN_SELECTORS).forEach(function (k) { if (s[BURN_SELECTORS[k]]) burnSels.push(k); });
    if (ctx.abi) {
      if (hasAbiFn(ctx.abi, /^mint|mint$|_mint|mintTo|increaseSupply/i)) mintSels.push('mint (ABI)');
      if (hasAbiFn(ctx.abi, /^burn|burn$|_burn|burnFrom|decreaseSupply/i)) burnSels.push('burn (ABI)');
    }

    var mintCap = ctx.capabilities.mint, burnCap = ctx.capabilities.burn;

    if (mintSels.length) {
      mintCap.present = true; mintCap.restriction = 'unknown';
      ctx.findings.push(createFinding({
        id: 'mint-present', category: 'mint', severity: 'MEDIUM', confidence: 'MEDIUM', exploitability: 0.5,
        title: 'Mint capability present — access control unknown',
        description: 'A mint function (' + mintSels.join(', ') + ') was detected. Static bytecode/ABI analysis cannot determine whether it is owner/role-restricted or callable by anyone, so unrestricted minting cannot be ruled out.',
        evidence: [
          { kind: 'OBSERVED', text: 'mint selector(s): ' + mintSels.join(', ') },
          { kind: 'UNKNOWN', text: 'access restriction on mint' }
        ],
        recommendation: 'Confirm from the source that mint is restricted to a trusted role. Unrestricted mint is the highest-severity token risk.'
      }));
    }

    if (burnSels.length) {
      burnCap.present = true; burnCap.restriction = 'unknown';
      ctx.findings.push(createFinding({
        id: 'burn-present', category: 'burn', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.3,
        title: 'Burn capability present',
        description: 'A burn function (' + burnSels.join(', ') + ') was detected.',
        evidence: [{ kind: 'OBSERVED', text: 'burn selector(s): ' + burnSels.join(', ') }],
        recommendation: 'Burn is generally low risk unless callable on arbitrary users\u2019 balances.'
      }));
    }
  }

  function rulePauseBlacklistFees(ctx) {
    var s = ctx.selectors;
    var cap = ctx.capabilities;

    if (s[PAUSE_SELECTORS.pause] && s[PAUSE_SELECTORS.unpause]) {
      cap.pause = 'Detected';
      ctx.findings.push(createFinding({
        id: 'pause-mechanism', category: 'pause', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.4,
        title: 'Pause/unpause mechanism detected',
        description: 'pause() and unpause() selectors are present.',
        evidence: [{ kind: 'OBSERVED', text: 'pause/unpause selectors' }, { kind: 'UNKNOWN', text: 'who can pause, and what it blocks' }],
        recommendation: 'Verify only a trusted role can pause and that it cannot be abused to freeze user funds.'
      }));
    } else {
      cap.pause = 'Unknown';
    }

    // Blacklist / whitelist / fees are non-standard (no stable selector). Only
    // detectable via ABI names; otherwise honestly report UNKNOWN.
    if (ctx.abi) {
      if (hasAbiFn(ctx.abi, /blacklist|unblacklist|isBlacklisted|setBlacklist/i)) {
        cap.blacklist = 'Detected';
        ctx.findings.push(createFinding({
          id: 'blacklist-mechanism', category: 'blacklist', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.5,
          title: 'Blacklist mechanism detected',
          description: 'ABI exposes blacklist functions.',
          evidence: [{ kind: 'OBSERVED', text: 'blacklist function(s) in ABI' }, { kind: 'UNKNOWN', text: 'who can blacklist; permanence' }],
          recommendation: 'A blacklist can freeze transfers. Verify it is admin-only and reversible.'
        }));
      } else { cap.blacklist = 'Unknown'; }
      if (hasAbiFn(ctx.abi, /whitelist|setWhitelist|isWhitelisted/i)) {
        cap.whitelist = 'Detected';
        ctx.findings.push(createFinding({
          id: 'whitelist-mechanism', category: 'whitelist', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.4,
          title: 'Whitelist mechanism detected',
          description: 'ABI exposes whitelist functions.',
          evidence: [{ kind: 'OBSERVED', text: 'whitelist function(s) in ABI' }],
          recommendation: 'Confirm the whitelist cannot lock out legitimate users.'
        }));
      } else { cap.whitelist = 'Unknown'; }
      if (hasAbiFn(ctx.abi, /fee|tax|buyFee|sellFee|transferFee|marketingFee|liquidityFee/i)) {
        cap.fees = 'Detected';
        ctx.findings.push(createFinding({
          id: 'fee-mechanism', category: 'fees', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.4,
          title: 'Fee/tax mechanism detected',
          description: 'ABI exposes fee/tax functions.',
          evidence: [{ kind: 'OBSERVED', text: 'fee/tax function(s) in ABI' }, { kind: 'UNKNOWN', text: 'fee values and limits' }],
          recommendation: 'Verify fee bounds; excessive or mutable fees can drain users.'
        }));
      } else { cap.fees = 'Unknown'; }
    } else {
      cap.blacklist = 'Unknown';
      cap.whitelist = 'Unknown';
      cap.fees = 'Unknown';
    }
  }

  // ── 7. Orchestrator ────────────────────────────────────────────────────────
  function analyze(bytecode, opts) {
    opts = opts || {};
    var address = opts.address || '';
    var chainId = opts.chainId || null;
    var abi = opts.abi || null;

    var cap = {
      ownership: 'Unknown',
      mint: { present: false, restriction: 'unknown' },
      burn: { present: false, restriction: 'unknown' },
      pause: 'Unknown',
      blacklist: 'Unknown',
      whitelist: 'Unknown',
      fees: 'Unknown',
      proxy: { detected: false, confidence: null, implementation: 'UNKNOWN', admin: 'UNKNOWN', upgradeable: 'UNKNOWN' },
      upgradeability: 'UNKNOWN'
    };

    var result = {
      contract: { address: address, chainId: chainId, type: 'Unknown', bytecodeSize: 0 },
      analysis: { completeness: 'minimal', analyzerVersion: VERSION, timestamp: Date.now() },
      risk: { score: 100, level: 'LIMITED ANALYSIS', confidence: 'LOW' },
      findings: [],
      capabilities: cap,
      observed: [],
      inferred: [],
      unknown: []
    };

    var hex = normalizeHex(bytecode);
    if (hex === null) {
      result.findings.push(createFinding({
        id: 'bytecode-invalid', category: 'bytecode', severity: 'INFO', confidence: 'HIGH',
        title: 'Invalid bytecode',
        description: 'The provided bytecode is not valid hexadecimal and could not be disassembled.',
        evidence: [{ kind: 'OBSERVED', text: 'bytecode failed hex validation' }],
        recommendation: 'Re-check the bytecode source.'
      }));
      result.analysis.completeness = 'minimal';
      result.risk = assessRisk(result.findings, 'minimal');
      result.risk.level = 'LIMITED ANALYSIS';
      return result;
    }

    if (hex === '') {
      result.analysis.completeness = 'minimal';
      result.risk = assessRisk(result.findings, 'minimal');
      result.risk.level = 'LIMITED ANALYSIS';
      result.contract.type = 'EOA';
      return result;
    }

    var dis = disassemble(hex);
    var bodyLen = hex.length / 2;
    result.contract.bytecodeSize = bodyLen;
    result.analysis.completeness = abi ? 'full' : 'partial';

    // Raw opcode observations
    var ops = {
      CALL: [], CALLCODE: [], DELEGATECALL: [], STATICCALL: [],
      SELFDESTRUCT: [], CREATE: [], CREATE2: [], ORIGIN: [], CALLER: [],
      SLOAD: 0, SSTORE: 0, JUMP: 0, JUMPI: 0, JUMPDEST: 0
    };
    dis.instructions.forEach(function (ins) {
      switch (ins.opcode) {
        case 'CALL': ops.CALL.push(ins.pc); break;
        case 'CALLCODE': ops.CALLCODE.push(ins.pc); break;
        case 'DELEGATECALL': ops.DELEGATECALL.push(ins.pc); break;
        case 'STATICCALL': ops.STATICCALL.push(ins.pc); break;
        case 'SELFDESTRUCT': ops.SELFDESTRUCT.push(ins.pc); break;
        case 'CREATE': ops.CREATE.push(ins.pc); break;
        case 'CREATE2': ops.CREATE2.push(ins.pc); break;
        case 'ORIGIN': ops.ORIGIN.push(ins.pc); break;
        case 'CALLER': ops.CALLER.push(ins.pc); break;
        case 'SLOAD': ops.SLOAD++; break;
        case 'SSTORE': ops.SSTORE++; break;
        case 'JUMP': ops.JUMP++; break;
        case 'JUMPI': ops.JUMPI++; break;
        case 'JUMPDEST': ops.JUMPDEST++; break;
      }
    });

    var collected = collectSelectors(dis.instructions);
    var ctx = {
      instructions: dis.instructions,
      ops: ops,
      bodyLen: bodyLen,
      selectors: collected.selectors,
      push32: collected.push32,
      push20: collected.push20,
      abi: abi,
      contract: result.contract,
      capabilities: cap,
      findings: result.findings,
      observed: result.observed,
      inferred: result.inferred,
      unknown: result.unknown
    };

    // Observe (facts)
    if (ops.DELEGATECALL.length) result.observed.push('DELEGATECALL at PC ' + ops.DELEGATECALL.join(','));
    if (ops.CALL.length) result.observed.push('CALL at PC ' + ops.CALL.join(','));
    if (ops.SELFDESTRUCT.length) result.observed.push('SELFDESTRUCT at PC ' + ops.SELFDESTRUCT.join(','));
    if (ops.ORIGIN.length) result.observed.push('ORIGIN at PC ' + ops.ORIGIN.join(','));
    if (ops.SSTORE > 0) result.observed.push('SSTORE x' + ops.SSTORE);

    // Run rules
    ruleBytecodeSize(ctx);
    ruleExternalCalls(ctx);
    ruleSelfdestruct(ctx);
    ruleTxOrigin(ctx);
    ruleStorage(ctx);
    ruleToken(ctx);
    ruleProxy(ctx);
    ruleOwnership(ctx);
    ruleMintBurn(ctx);
    rulePauseBlacklistFees(ctx);

    cap.upgradeability = cap.proxy.detected ? (cap.proxy.upgradeable === 'Detected' ? 'Detected' : 'Unknown') : 'NotDetected';

    // Sort findings by severity then confidence
    var sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    var confRank = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    result.findings.sort(function (a, b) {
      return (sevRank[a.severity] - sevRank[b.severity]) || (confRank[a.confidence] - confRank[b.confidence]);
    });

    result.risk = assessRisk(result.findings, result.analysis.completeness);

    // Inferred / unknown summaries (kept separate from observed facts)
    if (cap.proxy.detected) result.inferred.push('proxy pattern (' + cap.proxy.confidence + ' confidence)');
    if (cap.ownership === 'Detected') result.inferred.push('Ownable-style ownership');
    if (cap.mint.present) result.inferred.push('mint capability, restriction unknown');
    if (!abi) result.unknown.push('ABI not provided — administrative/privileged functions could not be fully enumerated');

    result.summary = buildSummary(result);
    result.analysisText = result.summary;
    result.context = buildContext(result, hex);

    return result;
  }

  function buildSummary(result) {
    var risk = result.risk;
    var significant = result.findings.filter(function (f) { return f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM'; });
    var s = 'Local static analysis: **' + risk.level + '** (score ' + risk.score + '/100, confidence ' + risk.confidence + ').';
    if (significant.length === 0) {
      s += ' No known issues were detected by the local static analyzer (bytecode heuristics).';
    } else {
      var top = significant.slice(0, 3).map(function (f) { return f.title; }).join('; ');
      s += ' Top signals: ' + top + '.';
    }
    if (risk.level === 'LIMITED ANALYSIS') {
      s += ' Analysis is limited (no or invalid bytecode) — no conclusion about safety is made.';
    } else {
      s += ' This is not a guarantee of safety; it reflects only what linear static bytecode/ABI analysis (no control-flow analysis) can observe.';
    }
    return s;
  }

  function buildContext(result, hex) {
    var lines = [];
    lines.push('Contract: ' + result.contract.address);
    lines.push('Type: ' + result.contract.type + ' (bytecode ' + result.contract.bytecodeSize + ' bytes)');
    lines.push('Risk: ' + result.risk.level + ' (' + result.risk.score + '/100)');
    lines.push('Bytecode (truncated): ' + (hex.length > 8000 ? hex.slice(0, 8000) : hex));
    result.findings.forEach(function (f) {
      lines.push(f.severity + ' [' + f.confidence + '] ' + f.title + ' — ' + f.description);
    });
    return lines.join('\n').slice(0, 8000);
  }

  // ── 8. Async entry (fetch bytecode via provider) ──────────────────────────
  async function auditContract(opts) {
    opts = opts || {};
    var address = opts.address || '';
    var provider = opts.provider || null;
    var code = opts.bytecode || null;
    var rpcUnavailable = false;

    if (!code && provider) {
      try { code = await provider.getCode(address); }
      catch (e) { code = null; rpcUnavailable = true; }
    } else if (!code && !provider) {
      rpcUnavailable = true;
    }

    var result = analyze(code, { address: address, chainId: opts.chainId, abi: opts.abi });
    result.analysis.rpcUnavailable = rpcUnavailable;
    result.code = code || '';
    return result;
  }

  // ── 9. Public API helpers ──────────────────────────────────────────────────
  var _last = null;
  function getFindings(result) { return (result || _last).findings; }
  function getRisk(result) { return (result || _last).risk; }
  function getContractInfo(result) {
    var r = result || _last;
    return { contract: r.contract, capabilities: r.capabilities };
  }
  function explainFinding(f) {
    return '**' + f.title + '** (' + f.severity + ', ' + f.confidence + ' confidence)\n\n' +
      (f.description || '') + '\n\nEvidence:\n' +
      (f.evidence || []).map(function (e) { return '• ' + e.kind + ': ' + e.text; }).join('\n') +
      (f.recommendation ? '\n\nRecommendation: ' + f.recommendation : '');
  }

  return {
    VERSION: VERSION,
    normalizeHex: normalizeHex,
    disassemble: disassemble,
    analyze: analyze,
    auditContract: auditContract,
    getFindings: getFindings,
    getRisk: getRisk,
    getContractInfo: getContractInfo,
    explainFinding: explainFinding,
    scoreImpact: scoreImpact,
    // Test/advanced access (documented as internal):
    createFinding: createFinding,
    assessRisk: assessRisk,
    levelFromScore: levelFromScore
  };
});
