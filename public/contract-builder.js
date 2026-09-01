// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Smart Contract Builder (Phase 7, Part B)
//
// A deterministic, zero-LLM Solidity contract generator + validator used by the
// Chat UI. It NEVER deploys anything by itself and NEVER fabricates addresses,
// transaction hashes, or deployment results. Generation and deployment are
// strictly separate steps (see index.html for the explicit-approval flow).
//
// Responsibilities:
//   isCreateIntent      — detect CREATE_CONTRACT vs AUDIT_CONTRACT
//   parseSpec           — turn a user description into a contract specification
//   generateSolidity    — deterministic Solidity source from a specification
//   validateSolidity    — structural validation (no full compilation)
//   securityWarnings    — honest warnings for dangerous specs (no silent edits)
//   constructorArgs     — deployment constructor parameters
//   preview             — structured preview for the UI
//
// Works in browser and Node (tests). No external AI/security API.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIContractBuilder = api;
})(function () {
  'use strict';

  var VERSION = '1.0.0';
  var SOLIDITY_VERSION = '0.8.20';

  // ── Intent detection ───────────────────────────────────────────────────────
  // Distinguish CREATE_CONTRACT from AUDIT_CONTRACT. `hasAddress` should be true
  // when a 0x… address was already matched in the message.
  var CREATE_PATTERN = /\b(create|make|generate|build|deploy|write)\b/i;
  var CONTRACT_WORD = /\b(contract|token|erc-?20|erc20|erc-?721|erc721|nft|escrow|vault|wallet|dao|stake|staking)\b/i;
  var AUDIT_PATTERN = /\b(audit|scan|analy[sz]e|review|check|inspect)\b/i;

  function isCreateIntent(text, hasAddress) {
    if (!text) return false;
    if (hasAddress) return false; // an address present => audit/scan context
    var t = String(text);
    if (AUDIT_PATTERN.test(t) && !CREATE_PATTERN.test(t)) return false;
    return CREATE_PATTERN.test(t) && CONTRACT_WORD.test(t);
  }

  // ── Amount parsing (deterministic) ─────────────────────────────────────────
  function parseAmount(text) {
    if (!text) return null;
    var t = String(text).toLowerCase().replace(/,/g, '');
    var m = t.match(/(\d+(?:\.\d+)?)\s*(million|m|thousand|k|billion|b)?/i);
    if (!m) return null;
    var n = parseFloat(m[1]);
    if (isNaN(n)) return null;
    var unit = (m[2] || '').toLowerCase();
    if (unit === 'million' || unit === 'm') n *= 1e6;
    else if (unit === 'billion' || unit === 'b') n *= 1e9;
    else if (unit === 'thousand' || unit === 'k') n *= 1e3;
    return Math.round(n);
  }

  // ── Specification parsing ──────────────────────────────────────────────────
  function detectType(text) {
    var t = String(text || '').toLowerCase();
    if (/erc-?20|erc20|token\b/.test(t)) return 'erc20';
    if (/escrow/.test(t)) return 'escrow';
    if (/erc-?721|erc721|nft/.test(t)) return 'erc721';
    return 'storage';
  }

  function parseName(text) {
    var m = String(text || '').match(/(?:called|named)\s+([A-Za-z][A-Za-z0-9_]*)/);
    return m ? m[1] : null;
  }

  function parseSymbol(text) {
    var m = String(text || '').match(/\bsymbol\s+([A-Za-z][A-Za-z0-9]{0,9})\b/i);
    return m ? m[1].toUpperCase() : null;
  }

  function defaultSymbol(name) {
    var s = (name || 'Token').replace(/[^A-Za-z0-9]/g, '');
    if (!s) s = 'TOK';
    s = s.slice(0, 4).toUpperCase();
    if (s.length < 2) s = 'TOK';
    return s;
  }

  function parseSupply(text) {
    var m = String(text || '').match(/(\d+(?:\.\d+)?\s*(?:million|m|thousand|k|billion|b)?)\s*(?:initial\s+)?(?:supply|tokens)\b/i);
    if (!m) return null;
    return parseAmount(m[0]);
  }

  function parseSpec(text) {
    var type = detectType(text);
    var name = parseName(text) || (type === 'erc20' ? 'MyToken' : type === 'escrow' ? 'Escrow' : 'Storage');
    var spec = {
      type: type,
      name: name,
      mintable: /\bmintable\b/i.test(String(text || '')),
      pausable: /\bpausable\b/i.test(String(text || '')),
      burnable: /\bburnable\b/i.test(String(text || ''))
    };

    if (type === 'erc20') {
      spec.symbol = parseSymbol(text) || defaultSymbol(name);
      spec.supply = parseSupply(text) || 1000000;
    } else if (type === 'escrow') {
      spec.depositor = /\b(alice|depositor)\b/i.test(String(text)) ? 'depositor' : 'depositor';
      spec.beneficiary = 'beneficiary';
      spec.approver = 'approver';
    } else if (type === 'erc721') {
      spec.symbol = parseSymbol(text) || defaultSymbol(name);
    }

    return spec;
  }

  // ── Solidity generation (deterministic templates) ─────────────────────────
  function esc(name) {
    return String(name).replace(/[^A-Za-z0-9_]/g, '_');
  }

  function erc20Source(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    string public name = "' + spec.name.replace(/"/g, '') + '";\n' +
      '    string public symbol = "' + spec.symbol + '";\n' +
      '    uint8 public decimals = 18;\n' +
      '    uint256 public totalSupply;\n' +
      '    address public owner;\n\n' +
      '    mapping(address => uint256) public balanceOf;\n' +
      '    mapping(address => mapping(address => uint256)) public allowance;\n\n' +
      '    event Transfer(address indexed from, address indexed to, uint256 value);\n' +
      '    event Approval(address indexed owner, address indexed spender, uint256 value);\n\n' +
      '    modifier onlyOwner() {\n' +
      '        require(msg.sender == owner, "not owner");\n' +
      '        _;\n' +
      '    }\n\n' +
      '    constructor(uint256 initialSupply) {\n' +
      '        owner = msg.sender;\n' +
      '        _mint(msg.sender, initialSupply);\n' +
      '    }\n\n' +
      '    function transfer(address to, uint256 amount) external returns (bool) {\n' +
      '        require(to != address(0), "zero address");\n' +
      '        require(balanceOf[msg.sender] >= amount, "insufficient balance");\n' +
      '        balanceOf[msg.sender] -= amount;\n' +
      '        balanceOf[to] += amount;\n' +
      '        emit Transfer(msg.sender, to, amount);\n' +
      '        return true;\n' +
      '    }\n\n' +
      '    function approve(address spender, uint256 amount) external returns (bool) {\n' +
      '        allowance[msg.sender][spender] = amount;\n' +
      '        emit Approval(msg.sender, spender, amount);\n' +
      '        return true;\n' +
      '    }\n\n' +
      '    function transferFrom(address from, address to, uint256 amount) external returns (bool) {\n' +
      '        require(allowance[from][msg.sender] >= amount, "insufficient allowance");\n' +
      '        require(balanceOf[from] >= amount, "insufficient balance");\n' +
      '        allowance[from][msg.sender] -= amount;\n' +
      '        balanceOf[from] -= amount;\n' +
      '        balanceOf[to] += amount;\n' +
      '        emit Transfer(from, to, amount);\n' +
      '        return true;\n' +
      '    }\n\n' +
      '    function _mint(address to, uint256 amount) internal {\n' +
      '        totalSupply += amount;\n' +
      '        balanceOf[to] += amount;\n' +
      '        emit Transfer(address(0), to, amount);\n' +
      '    }\n\n' +
      (spec.mintable ? '    function mint(address to, uint256 amount) external onlyOwner {\n        _mint(to, amount);\n    }\n\n' : '') +
      (spec.burnable ? '    function burn(uint256 amount) external {\n        require(balanceOf[msg.sender] >= amount, "insufficient balance");\n        balanceOf[msg.sender] -= amount;\n        totalSupply -= amount;\n        emit Transfer(msg.sender, address(0), amount);\n    }\n\n' : '') +
      '}\n';
  }

  function storageSource(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    uint256 private value;\n' +
      '    address public owner;\n\n' +
      '    event ValueSet(address indexed setter, uint256 newValue);\n\n' +
      '    constructor() {\n' +
      '        owner = msg.sender;\n' +
      '    }\n\n' +
      '    modifier onlyOwner() {\n' +
      '        require(msg.sender == owner, "not owner");\n' +
      '        _;\n' +
      '    }\n\n' +
      '    function set(uint256 newValue) external onlyOwner {\n' +
      '        value = newValue;\n' +
      '        emit ValueSet(msg.sender, newValue);\n' +
      '    }\n\n' +
      '    function get() external view returns (uint256) {\n' +
      '        return value;\n' +
      '    }\n' +
      '}\n';
  }

  function escrowSource(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    address public depositor;\n' +
      '    address public beneficiary;\n' +
      '    address public approver;\n' +
      '    uint256 public amount;\n' +
      '    bool public released;\n' +
      '    bool public approved;\n\n' +
      '    event Deposited(address indexed from, uint256 amount);\n' +
      '    event Approved(address indexed approver);\n' +
      '    event Released(address indexed to, uint256 amount);\n\n' +
      '    constructor(address _beneficiary, address _approver) {\n' +
      '        depositor = msg.sender;\n' +
      '        beneficiary = _beneficiary;\n' +
      '        approver = _approver;\n' +
      '    }\n\n' +
      '    function deposit() external payable {\n' +
      '        require(msg.sender == depositor, "only depositor");\n' +
      '        require(!released, "already released");\n' +
      '        amount += msg.value;\n' +
      '        emit Deposited(msg.sender, msg.value);\n' +
      '    }\n\n' +
      '    function approve() external {\n' +
      '        require(msg.sender == approver, "only approver");\n' +
      '        approved = true;\n' +
      '        emit Approved(msg.sender);\n' +
      '    }\n\n' +
      '    function release() external {\n' +
      '        require(msg.sender == beneficiary, "only beneficiary");\n' +
      '        require(approved, "not approved");\n' +
      '        require(!released, "already released");\n' +
      '        released = true;\n' +
      '        payable(beneficiary).transfer(amount);\n' +
      '        emit Released(beneficiary, amount);\n' +
      '    }\n' +
      '}\n';
  }

  function erc721Source(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    string public name = "' + spec.name.replace(/"/g, '') + '";\n' +
      '    string public symbol = "' + spec.symbol + '";\n' +
      '    address public owner;\n' +
      '    uint256 public totalSupply;\n\n' +
      '    mapping(uint256 => address) private _owners;\n' +
      '    mapping(address => uint256) private _balances;\n' +
      '    mapping(uint256 => string) private _tokenURIs;\n\n' +
      '    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);\n\n' +
      '    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n\n' +
      '    constructor() { owner = msg.sender; }\n\n' +
      '    function mint(address to, uint256 tokenId, string memory uri) external onlyOwner {\n' +
      '        require(_owners[tokenId] == address(0), "already minted");\n' +
      '        _owners[tokenId] = to;\n' +
      '        _balances[to] += 1;\n' +
      '        totalSupply += 1;\n' +
      '        _tokenURIs[tokenId] = uri;\n' +
      '        emit Transfer(address(0), to, tokenId);\n' +
      '    }\n\n' +
      '    function ownerOf(uint256 tokenId) external view returns (address) {\n' +
      '        return _owners[tokenId];\n' +
      '    }\n\n' +
      '    function tokenURI(uint256 tokenId) external view returns (string memory) {\n' +
      '        return _tokenURIs[tokenId];\n' +
      '    }\n' +
      '}\n';
  }

  function generateSolidity(spec) {
    spec = spec || {};
    if (spec.type === 'erc20') return erc20Source(spec);
    if (spec.type === 'escrow') return escrowSource(spec);
    if (spec.type === 'erc721') return erc721Source(spec);
    return storageSource(spec);
  }

  // ── Structural validation (no full compilation) ────────────────────────────
  function validateSolidity(source) {
    var errors = [];
    if (typeof source !== 'string' || !source.trim()) {
      return { valid: false, errors: ['empty source'] };
    }
    if (!/pragma\s+solidity/i.test(source)) errors.push('missing `pragma solidity` directive');
    if (!/contract\s+[A-Za-z_][A-Za-z0-9_]*/.test(source)) errors.push('missing contract declaration');

    // Brace / paren balance.
    var stack = [];
    var pairs = { '{': '}', '(': ')', '[': ']' };
    var closers = { '}': '{', ')': '(', ']': '[' };
    for (var i = 0; i < source.length; i++) {
      var ch = source[i];
      if (pairs[ch]) stack.push(ch);
      else if (closers[ch]) {
        if (stack.pop() !== closers[ch]) { errors.push('unbalanced delimiter at position ' + i); break; }
      }
    }
    if (stack.length) errors.push('unbalanced delimiters (missing closing)');

    // Secret storage guard — never generate a contract that embeds a secret.
    if (/(private\s*key|mnemonic|seed\s*phrase|api[_-]?key|secret\s*key)/i.test(source)) {
      errors.push('source embeds a secret/credential');
    }

    return { valid: errors.length === 0, errors: errors };
  }

  // ── Security warnings (honest; never silently edits the spec) ─────────────
  function securityWarnings(spec, source) {
    spec = spec || {};
    var warnings = [];
    if (spec.type === 'erc20' && spec.mintable) {
      warnings.push({ level: 'HIGH', text: 'Mintable token: `mint()` is owner-restricted by `onlyOwner`, but an owner-controlled mint can still inflate supply. Verify the owner is trusted.' });
    }
    if (spec.type === 'erc20' && !spec.mintable) {
      warnings.push({ level: 'INFO', text: 'Fixed supply: no minting after deployment. The total supply is set once in the constructor.' });
    }
    if (/selfdestruct|SELFDESTRUCT/.test(source || '')) {
      warnings.push({ level: 'HIGH', text: 'Contract contains selfdestruct.' });
    }
    if (/delegatecall/.test(source || '')) {
      warnings.push({ level: 'MEDIUM', text: 'Contract uses delegatecall — verify the target is trusted.' });
    }
    if (spec.type === 'escrow') {
      warnings.push({ level: 'INFO', text: 'Escrow uses `transfer` in `release()`; review for reentrancy concerns (state is set before the transfer).' });
    }
    if (!warnings.length) warnings.push({ level: 'INFO', text: 'No obvious dangerous patterns detected in the generated source.' });
    return warnings;
  }

  // ── Constructor arguments for deployment ──────────────────────────────────
  function constructorArgs(spec) {
    spec = spec || {};
    if (spec.type === 'erc20') {
      var wei = spec.supply;
      // deterministic: store raw units + wei string (18 decimals)
      var big = wei.toString() + '000000000000000000';
      return [{ name: 'initialSupply', type: 'uint256', value: big, label: 'Initial supply (wei, 18 decimals)', units: String(wei) }];
    }
    if (spec.type === 'escrow') {
      return [
        { name: '_beneficiary', type: 'address', value: '', label: 'Beneficiary address' },
        { name: '_approver', type: 'address', value: '', label: 'Approver address' }
      ];
    }
    return [];
  }

  // ── Preview object for the UI ──────────────────────────────────────────────
  function preview(spec, source, network) {
    spec = spec || {};
    return {
      type: spec.type,
      name: spec.name,
      symbol: spec.symbol || null,
      supply: spec.supply || null,
      solidityVersion: SOLIDITY_VERSION,
      source: source,
      constructorArgs: constructorArgs(spec),
      warnings: securityWarnings(spec, source),
      network: network || null
    };
  }

  return {
    VERSION: VERSION,
    SOLIDITY_VERSION: SOLIDITY_VERSION,
    isCreateIntent: isCreateIntent,
    detectType: detectType,
    parseName: parseName,
    parseSymbol: parseSymbol,
    parseSupply: parseSupply,
    parseAmount: parseAmount,
    parseSpec: parseSpec,
    generateSolidity: generateSolidity,
    validateSolidity: validateSolidity,
    securityWarnings: securityWarnings,
    constructorArgs: constructorArgs,
    preview: preview
  };
});
