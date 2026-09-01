// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Contract Templates (Phase 7.2, Contract Studio 2.0)
//
// Deterministic contract templates + specification validation. This module is
// responsible ONLY for:
//   - the contract-type catalog (EVM Solidity + GenLayer Python)
//   - default / validated specifications
//   - deterministic source generation
//   - specHash / sourceHash / builderVersion (reproducibility)
//   - constructor arguments
//   - deployment capability (honest — never claims a transport that isn't wired)
//
// It does NOT deploy, does NOT audit, and NEVER fabricates addresses/txs.
// Works in browser and Node (tests). No external AI/security API.
// ═══════════════════════════════════════════════════════════════════════════════
(function (factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
  (typeof globalThis !== 'undefined' ? globalThis : window).AuditAIContractTemplates = api;
})(function () {
  'use strict';

  var BUILDER_VERSION = '2.0.0';
  var SOLIDITY_VERSION = '0.8.20';

  // ── Deterministic hashing (FNV-1a 32-bit) ─────────────────────────────────
  function fnv1a(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  function stableStringify(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
    var keys = Object.keys(obj).sort();
    return '{' + keys.map(function (k) { return JSON.stringify(k) + ':' + stableStringify(obj[k]); }).join(',') + '}';
  }

  function specHash(spec) { return fnv1a(stableStringify(spec || {})); }
  function sourceHash(source) { return fnv1a(String(source || '')); }

  // ── Contract-type catalog ──────────────────────────────────────────────────
  // family: 'EVM' (Solidity) | 'GENLAYER' (Python intelligent contract)
  var CONTRACT_TYPES = {
    erc20:      { key: 'erc20',      label: 'ERC-20 Token',          family: 'EVM',      kind: 'solidity' },
    erc721:     { key: 'erc721',     label: 'ERC-721 NFT',           family: 'EVM',      kind: 'solidity' },
    erc1155:    { key: 'erc1155',    label: 'ERC-1155 Multi Token',  family: 'EVM',      kind: 'solidity' },
    escrow:     { key: 'escrow',     label: 'Escrow',                family: 'EVM',      kind: 'solidity' },
    staking:    { key: 'staking',    label: 'Staking',               family: 'EVM',      kind: 'solidity' },
    vesting:    { key: 'vesting',    label: 'Vesting',               family: 'EVM',      kind: 'solidity' },
    treasury:   { key: 'treasury',   label: 'Treasury',              family: 'EVM',      kind: 'solidity' },
    timelock:   { key: 'timelock',   label: 'Timelock',              family: 'EVM',      kind: 'solidity' },
    custom:     { key: 'custom',     label: 'Custom Solidity',       family: 'EVM',      kind: 'solidity' },
    genlayer_intelligent: { key: 'genlayer_intelligent', label: 'Intelligent Contract',       family: 'GENLAYER', kind: 'python' },
    genlayer_ai:          { key: 'genlayer_ai',          label: 'AI Decision Contract',       family: 'GENLAYER', kind: 'python' },
    genlayer_custom:      { key: 'genlayer_custom',      label: 'Custom Intelligent Contract', family: 'GENLAYER', kind: 'python' }
  };

  var EVM_TYPES = ['erc20', 'erc721', 'erc1155', 'escrow', 'staking', 'vesting', 'treasury', 'timelock', 'custom'];
  var GENLAYER_TYPES = ['genlayer_intelligent', 'genlayer_ai', 'genlayer_custom'];

  function getType(key) { return CONTRACT_TYPES[key] || null; }
  function allTypes() { return Object.keys(CONTRACT_TYPES); }

  function esc(name) {
    var s = String(name || '').replace(/[^A-Za-z0-9_]/g, '_');
    if (!s) s = 'Contract';
    if (/^[0-9]/.test(s)) s = 'C' + s;
    return s;
  }

  // ── Default specifications ─────────────────────────────────────────────────
  function defaultSpec(type) {
    var base = { type: type };
    switch (type) {
      case 'erc20':
        return {
          type: 'erc20', name: 'MyToken', symbol: 'MTK', decimals: 18, supply: 1000000,
          supplyType: 'fixed', burn: false, pause: false, accessControl: 'none',
          permit: false, votes: false, fee: 'none'
        };
      case 'erc721':
        return { type: 'erc721', name: 'MyNFT', symbol: 'MNFT', baseURI: '', startingTokenId: 0, mintable: true, burn: false, pause: false, accessControl: 'ownable', royalty: false, enumerable: false };
      case 'erc1155':
        return { type: 'erc1155', name: 'MyMultiToken', uri: '', mintable: true, burn: false, pause: false, accessControl: 'ownable', supplyTracking: false };
      case 'escrow':
        return { type: 'escrow', name: 'Escrow', assetType: 'native', buyer: '', seller: '', arbiter: '', amount: '0', timeout: 0 };
      case 'staking':
        return { type: 'staking', name: 'Staking', stakeToken: '', rewardToken: '', rewardModel: 'unconfigured', lockPeriod: 0, unstake: true, emergencyWithdrawal: true, adminControls: 'ownable' };
      case 'vesting':
        return { type: 'vesting', name: 'Vesting', beneficiary: '', token: '', totalAmount: '0', start: 0, cliff: 0, duration: 0, revocable: false };
      case 'treasury':
        return { type: 'treasury', name: 'Treasury', owner: '', assets: [], spendingLimit: '0', approvers: [], emergencyControls: true };
      case 'timelock':
        return { type: 'timelock', name: 'Timelock', admin: '', minDelay: 86400, proposers: [], executors: [], cancellable: true };
      case 'custom':
        return { type: 'custom', name: 'CustomContract', source: '' };
      case 'genlayer_intelligent':
        return { type: 'genlayer_intelligent', name: 'Counter', description: 'A simple key-value counter contract.' };
      case 'genlayer_ai':
        return { type: 'genlayer_ai', name: 'AIDecision', description: 'An AI decision contract using the equivalence principle.' };
      case 'genlayer_custom':
        return { type: 'genlayer_custom', name: 'CustomIntelligent', source: '' };
      default:
        return base;
    }
  }

  // ── Specification validation ───────────────────────────────────────────────
  // Returns { valid, errors, warnings }. Unsupported options are rejected with
  // NOT_IMPLEMENTED (never silently generate incomplete code).
  function validateSpec(spec) {
    var errors = [], warnings = [];
    spec = spec || {};
    if (!CONTRACT_TYPES[spec.type]) { errors.push('unknown contract type: ' + spec.type); return { valid: false, errors: errors, warnings: warnings }; }

    if (spec.type === 'custom' || spec.type === 'genlayer_custom') {
      if (!spec.source || !String(spec.source).trim()) errors.push('source code is required for ' + spec.type);
      return { valid: errors.length === 0, errors: errors, warnings: warnings };
    }

    if (!spec.name || !String(spec.name).trim()) errors.push('name is required');
    else if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(String(spec.name).trim())) errors.push('name must be a valid identifier');

    if (spec.type === 'erc20') {
      if (spec.permit) errors.push('NOT_IMPLEMENTED: EIP-2612 Permit is not yet implemented');
      if (spec.votes) errors.push('NOT_IMPLEMENTED: Governance/Votes is not yet implemented');
      if (spec.fee && spec.fee !== 'none') errors.push('NOT_IMPLEMENTED: custom transfer fee is not yet implemented');
      if (spec.decimals === undefined || spec.decimals < 0 || spec.decimals > 18) errors.push('decimals must be between 0 and 18');
      if (spec.supply === undefined || spec.supply < 0) errors.push('supply must be >= 0');
      if (spec.supplyType !== 'fixed' && spec.supplyType !== 'mintable') errors.push('supplyType must be fixed or mintable');
      if (['none', 'ownable', 'accesscontrol'].indexOf(spec.accessControl) === -1) errors.push('accessControl must be none, ownable, or accesscontrol');
    }
    if (spec.type === 'erc721' || spec.type === 'erc1155') {
      if (spec.royalty && spec.type === 'erc721') errors.push('NOT_IMPLEMENTED: ERC-721 royalty is not yet implemented');
      if (spec.type === 'erc721' && spec.enumerable) errors.push('NOT_IMPLEMENTED: ERC-721 Enumerable is not yet implemented');
    }
    if (spec.type === 'staking') {
      if (!spec.rewardModel || spec.rewardModel === 'unconfigured') errors.push('staking reward model must be configured (e.g. rewardModel: "fixed-rate") before deployment');
    }
    if (spec.type === 'escrow') {
      if (spec.assetType !== 'native' && spec.assetType !== 'erc20') errors.push('assetType must be native or erc20');
    }
    return { valid: errors.length === 0, errors: errors, warnings: warnings };
  }

  // ── Solidity templates (EVM family) ────────────────────────────────────────
  function _erc20Source(spec) {
    var N = esc(spec.name);
    var ac = spec.accessControl;
    var ownable = ac === 'ownable';
    var accessControl = ac === 'accesscontrol';
    var mintable = spec.supplyType === 'mintable';
    var pausable = !!spec.pause;
    var burnable = !!spec.burn;
    var dec = spec.decimals;

    var out = '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    string public name = "' + String(spec.name).replace(/"/g, '') + '";\n' +
      '    string public symbol = "' + String(spec.symbol).replace(/"/g, '') + '";\n' +
      '    uint8 public decimals = ' + dec + ';\n' +
      '    uint256 public totalSupply;\n\n';

    // Access control scaffolding (only when requested — never dead ownership).
    if (ownable) {
      out += '    address public owner;\n\n' +
        '    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);\n\n' +
        '    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n\n' +
        '    function transferOwnership(address newOwner) external onlyOwner {\n' +
        '        require(newOwner != address(0), "zero address");\n' +
        '        emit OwnershipTransferred(owner, newOwner);\n' +
        '        owner = newOwner;\n' +
        '    }\n\n';
    } else if (accessControl) {
      out += '    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;\n' +
        '    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");\n' +
        '    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");\n' +
        '    mapping(bytes32 => mapping(address => bool)) private _roles;\n\n' +
        '    modifier onlyRole(bytes32 role) { require(hasRole(role, msg.sender), "missing role"); _; }\n\n' +
        '    function hasRole(bytes32 role, address account) public view returns (bool) { return _roles[role][account]; }\n\n' +
        '    function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) { _roles[role][account] = true; }\n\n' +
        '    function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) { _roles[role][account] = false; }\n\n';
    }

    if (pausable) {
      out += '    bool public paused;\n\n' +
        '    event Paused(address indexed account);\n' +
        '    event Unpaused(address indexed account);\n\n';
      var pauseGuard = ownable ? 'onlyOwner' : (accessControl ? 'onlyRole(PAUSER_ROLE)' : null);
      if (pauseGuard) {
        out += '    modifier whenNotPaused() { require(!paused, "paused"); _; }\n\n' +
          '    function pause() external ' + pauseGuard + ' { paused = true; emit Paused(msg.sender); }\n\n' +
          '    function unpause() external ' + pauseGuard + ' { paused = false; emit Unpaused(msg.sender); }\n\n';
      }
    }

    out += '    mapping(address => uint256) public balanceOf;\n' +
      '    mapping(address => mapping(address => uint256)) public allowance;\n\n' +
      '    event Transfer(address indexed from, address indexed to, uint256 value);\n' +
      '    event Approval(address indexed owner, address indexed spender, uint256 value);\n\n';

    var mintGuard = mintable ? (ownable ? 'onlyOwner ' : (accessControl ? 'onlyRole(MINTER_ROLE) ' : '')) : '';
    out += '    constructor(uint256 initialSupply) {\n' +
      (ownable ? '        owner = msg.sender;\n' : '') +
      (accessControl ? '        _roles[DEFAULT_ADMIN_ROLE][msg.sender] = true;\n        _roles[MINTER_ROLE][msg.sender] = true;\n        _roles[PAUSER_ROLE][msg.sender] = true;\n' : '') +
      '        _mint(msg.sender, initialSupply);\n' +
      '    }\n\n';

    out += '    function transfer(address to, uint256 amount) external returns (bool) {\n' +
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
      '        require(to != address(0), "zero address");\n' +
      '        require(balanceOf[from] >= amount, "insufficient balance");\n' +
      '        require(allowance[from][msg.sender] >= amount, "insufficient allowance");\n' +
      '        allowance[from][msg.sender] -= amount;\n' +
      '        balanceOf[from] -= amount;\n' +
      '        balanceOf[to] += amount;\n' +
      '        emit Transfer(from, to, amount);\n' +
      '        return true;\n' +
      '    }\n\n' +
      '    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {\n' +
      '        allowance[msg.sender][spender] += addedValue;\n' +
      '        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);\n' +
      '        return true;\n' +
      '    }\n\n' +
      '    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {\n' +
      '        uint256 current = allowance[msg.sender][spender];\n' +
      '        require(current >= subtractedValue, "allowance underflow");\n' +
      '        allowance[msg.sender][spender] = current - subtractedValue;\n' +
      '        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);\n' +
      '        return true;\n' +
      '    }\n\n' +
      '    function _mint(address to, uint256 amount) internal {\n' +
      '        require(to != address(0), "zero address");\n' +
      '        totalSupply += amount;\n' +
      '        balanceOf[to] += amount;\n' +
      '        emit Transfer(address(0), to, amount);\n' +
      '    }\n\n';

    if (mintable) {
      out += '    function mint(address to, uint256 amount) external ' + (mintGuard ? mintGuard : '') + ' {\n' +
        '        _mint(to, amount);\n' +
        '    }\n\n';
    }
    if (burnable) {
      out += '    function burn(uint256 amount) external {\n' +
        '        require(balanceOf[msg.sender] >= amount, "insufficient balance");\n' +
        '        balanceOf[msg.sender] -= amount;\n' +
        '        totalSupply -= amount;\n' +
        '        emit Transfer(msg.sender, address(0), amount);\n' +
        '    }\n\n';
    }

    out += '}\n';
    return out;
  }

  function _erc721Source(spec) {
    var N = esc(spec.name);
    var ownable = spec.accessControl === 'ownable';
    var out = '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    string public name = "' + String(spec.name).replace(/"/g, '') + '";\n' +
      '    string public symbol = "' + String(spec.symbol).replace(/"/g, '') + '";\n' +
      '    string public baseURI = "' + String(spec.baseURI || '').replace(/"/g, '') + '";\n' +
      '    uint256 public totalSupply;\n' +
      (ownable ? '    address public owner;\n\n    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n\n    constructor() { owner = msg.sender; }\n\n' : '') +
      '    mapping(uint256 => address) private _owners;\n' +
      '    mapping(address => uint256) private _balances;\n' +
      '    mapping(uint256 => address) private _tokenApprovals;\n' +
      '    mapping(address => mapping(address => bool)) private _operatorApprovals;\n\n' +
      '    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);\n' +
      '    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);\n' +
      '    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);\n\n' +
      '    function mint(address to, uint256 tokenId) external ' + (ownable ? 'onlyOwner' : '') + ' {\n' +
      '        require(to != address(0), "zero address");\n' +
      '        require(_owners[tokenId] == address(0), "already minted");\n' +
      '        _owners[tokenId] = to;\n' +
      '        _balances[to] += 1;\n' +
      '        totalSupply += 1;\n' +
      '        emit Transfer(address(0), to, tokenId);\n' +
      '    }\n\n' +
      (spec.burn ? '    function burn(uint256 tokenId) external {\n        require(ownerOf(tokenId) == msg.sender, "not owner");\n        address o = _owners[tokenId];\n        _balances[o] -= 1;\n        delete _owners[tokenId];\n        totalSupply -= 1;\n        emit Transfer(o, address(0), tokenId);\n    }\n\n' : '') +
      '    function ownerOf(uint256 tokenId) public view returns (address) {\n' +
      '        address o = _owners[tokenId];\n' +
      '        require(o != address(0), "nonexistent token");\n' +
      '        return o;\n' +
      '    }\n\n' +
      '    function approve(address to, uint256 tokenId) external {\n' +
      '        address o = ownerOf(tokenId);\n' +
      '        require(msg.sender == o || _operatorApprovals[o][msg.sender], "not authorized");\n' +
      '        _tokenApprovals[tokenId] = to;\n' +
      '        emit Approval(o, to, tokenId);\n' +
      '    }\n\n' +
      '    function setApprovalForAll(address operator, bool approved) external {\n' +
      '        _operatorApprovals[msg.sender][operator] = approved;\n' +
      '        emit ApprovalForAll(msg.sender, operator, approved);\n' +
      '    }\n\n' +
      '    function transferFrom(address from, address to, uint256 tokenId) external {\n' +
      '        address o = ownerOf(tokenId);\n' +
      '        require(msg.sender == o || _tokenApprovals[tokenId] == msg.sender || _operatorApprovals[o][msg.sender], "not authorized");\n' +
      '        require(to != address(0), "zero address");\n' +
      '        _owners[tokenId] = to;\n' +
      '        _balances[from] -= 1;\n' +
      '        _balances[to] += 1;\n' +
      '        delete _tokenApprovals[tokenId];\n' +
      '        emit Transfer(from, to, tokenId);\n' +
      '    }\n\n' +
      '    function tokenURI(uint256 tokenId) external view returns (string memory) {\n' +
      '        require(_owners[tokenId] != address(0), "nonexistent token");\n' +
      '        return string(abi.encodePacked(baseURI));\n' +
      '    }\n' +
      '}\n';
    return out;
  }

  function _erc1155Source(spec) {
    var N = esc(spec.name);
    var ownable = spec.accessControl === 'ownable';
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    string public name = "' + String(spec.name).replace(/"/g, '') + '";\n' +
      (ownable ? '    address public owner;\n\n    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n\n    constructor() { owner = msg.sender; }\n\n' : '') +
      '    mapping(uint256 => mapping(address => uint256)) private _balances;\n' +
      '    mapping(address => mapping(address => bool)) private _operatorApprovals;\n\n' +
      '    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);\n' +
      '    event ApprovalForAll(address indexed account, address indexed operator, bool approved);\n\n' +
      '    function mint(address to, uint256 id, uint256 amount) external ' + (ownable ? 'onlyOwner' : '') + ' {\n' +
      '        require(to != address(0), "zero address");\n' +
      '        _balances[id][to] += amount;\n' +
      '        emit TransferSingle(msg.sender, address(0), to, id, amount);\n' +
      '    }\n\n' +
      (spec.burn ? '    function burn(address from, uint256 id, uint256 amount) external {\n        require(from == msg.sender || _operatorApprovals[from][msg.sender], "not authorized");\n        require(_balances[id][from] >= amount, "insufficient balance");\n        _balances[id][from] -= amount;\n        emit TransferSingle(msg.sender, from, address(0), id, amount);\n    }\n\n' : '') +
      '    function balanceOf(address account, uint256 id) external view returns (uint256) {\n' +
      '        return _balances[id][account];\n' +
      '    }\n\n' +
      '    function setApprovalForAll(address operator, bool approved) external {\n' +
      '        _operatorApprovals[msg.sender][operator] = approved;\n' +
      '        emit ApprovalForAll(msg.sender, operator, approved);\n' +
      '    }\n\n' +
      '    function safeTransferFrom(address from, address to, uint256 id, uint256 amount) external {\n' +
      '        require(from == msg.sender || _operatorApprovals[from][msg.sender], "not authorized");\n' +
      '        require(_balances[id][from] >= amount, "insufficient balance");\n' +
      '        _balances[id][from] -= amount;\n' +
      '        _balances[id][to] += amount;\n' +
      '        emit TransferSingle(msg.sender, from, to, id, amount);\n' +
      '    }\n' +
      '}\n';
  }

  function _escrowSource(spec) {
    var N = esc(spec.name);
    var native = spec.assetType === 'native';
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    enum State { CREATED, FUNDED, RELEASED, REFUNDED, DISPUTED }\n' +
      '    State public state = State.CREATED;\n' +
      '    address public buyer;\n' +
      '    address public seller;\n' +
      '    address public arbiter;\n' +
      '    uint256 public amount;\n' +
      '    uint256 public timeout;\n' +
      '    uint256 public fundedAt;\n\n' +
      '    event Funded(address indexed buyer, uint256 amount);\n' +
      '    event Released(address indexed to, uint256 amount);\n' +
      '    event Refunded(address indexed to, uint256 amount);\n' +
      '    event Disputed(address indexed by);\n\n' +
      '    modifier onlyBuyer() { require(msg.sender == buyer, "only buyer"); _; }\n' +
      '    modifier onlyArbiter() { require(msg.sender == arbiter, "only arbiter"); _; }\n\n' +
      '    constructor(address _seller, address _arbiter, uint256 _amount, uint256 _timeout) {\n' +
      '        require(_seller != address(0) && _arbiter != address(0), "zero address");\n' +
      '        buyer = msg.sender;\n' +
      '        seller = _seller;\n' +
      '        arbiter = _arbiter;\n' +
      '        amount = _amount;\n' +
      '        timeout = _timeout;\n' +
      '    }\n\n' +
      '    function fund() external payable onlyBuyer {\n' +
      '        require(state == State.CREATED, "not created");\n' +
      (native ? '        require(msg.value == amount, "wrong amount");\n' : '        require(msg.value == 0, "native not accepted");\n') +
      '        state = State.FUNDED;\n' +
      '        fundedAt = block.timestamp;\n' +
      '        emit Funded(msg.sender, amount);\n' +
      '    }\n\n' +
      '    function release() external onlyArbiter {\n' +
      '        require(state == State.FUNDED, "not funded");\n' +
      '        state = State.RELEASED;\n' +
      (native ? '        payable(seller).transfer(amount);\n' : '        // ERC-20 release must call token.transfer(seller, amount)\n') +
      '        emit Released(seller, amount);\n' +
      '    }\n\n' +
      '    function refund() external onlyArbiter {\n' +
      '        require(state == State.FUNDED, "not funded");\n' +
      '        state = State.REFUNDED;\n' +
      (native ? '        payable(buyer).transfer(amount);\n' : '        // ERC-20 refund must call token.transfer(buyer, amount)\n') +
      '        emit Refunded(buyer, amount);\n' +
      '    }\n\n' +
      '    function dispute() external onlyBuyer {\n' +
      '        require(state == State.FUNDED, "not funded");\n' +
      '        state = State.DISPUTED;\n' +
      '        emit Disputed(msg.sender);\n' +
      '    }\n\n' +
      '    function resolveDispute(bool releaseToSeller) external onlyArbiter {\n' +
      '        require(state == State.DISPUTED, "not disputed");\n' +
      '        state = releaseToSeller ? State.RELEASED : State.REFUNDED;\n' +
      (native ? '        payable(releaseToSeller ? seller : buyer).transfer(amount);\n' : '') +
      '        if (releaseToSeller) emit Released(seller, amount); else emit Refunded(buyer, amount);\n' +
      '    }\n' +
      '}\n';
  }

  function _stakingSource(spec) {
    var N = esc(spec.name);
    // Reward math requires explicit configuration; the template emits a guarded
    // stub that must be configured — no fictional reward formula is generated.
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    address public owner;\n' +
      '    address public stakeToken;\n' +
      '    address public rewardToken;\n' +
      '    uint256 public lockPeriod;\n' +
      '    uint256 public rewardRate; // configured by owner, not invented\n\n' +
      '    struct Position { uint256 amount; uint256 since; }\n' +
      '    mapping(address => Position) public positions;\n\n' +
      '    event Staked(address indexed user, uint256 amount);\n' +
      '    event Unstaked(address indexed user, uint256 amount);\n\n' +
      '    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n\n' +
      '    constructor(address _stakeToken, address _rewardToken, uint256 _lockPeriod, uint256 _rewardRate) {\n' +
      '        owner = msg.sender;\n' +
      '        stakeToken = _stakeToken;\n' +
      '        rewardToken = _rewardToken;\n' +
      '        lockPeriod = _lockPeriod;\n' +
      '        rewardRate = _rewardRate;\n' +
      '    }\n\n' +
      '    function stake(uint256 amount) external {\n' +
      '        // NOTE: token transfer requires an ERC-20 interface (not wired here).\n' +
      '        positions[msg.sender].amount += amount;\n' +
      '        positions[msg.sender].since = block.timestamp;\n' +
      '        emit Staked(msg.sender, amount);\n' +
      '    }\n\n' +
      '    function unstake() external {\n' +
      '        Position storage p = positions[msg.sender];\n' +
      '        require(p.amount > 0, "nothing staked");\n' +
      '        require(block.timestamp >= p.since + lockPeriod, "locked");\n' +
      '        uint256 amt = p.amount;\n' +
      '        p.amount = 0;\n' +
      '        emit Unstaked(msg.sender, amt);\n' +
      '        // NOTE: token transfer back to user must be wired with a real token interface.\n' +
      '    }\n\n' +
      '    function setRewardRate(uint256 rate) external onlyOwner { rewardRate = rate; }\n' +
      '}\n';
  }

  function _vestingSource(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    address public owner;\n' +
      '    address public beneficiary;\n' +
      '    address public token;\n' +
      '    uint256 public totalAmount;\n' +
      '    uint256 public start;\n' +
      '    uint256 public cliff;\n' +
      '    uint256 public duration;\n' +
      '    uint256 public released;\n' +
      '    bool public revoked;\n\n' +
      '    event Released(address indexed to, uint256 amount);\n' +
      '    event Revoked();\n\n' +
      '    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n\n' +
      '    constructor(address _beneficiary, address _token, uint256 _totalAmount, uint256 _start, uint256 _cliff, uint256 _duration) {\n' +
      '        owner = msg.sender;\n' +
      '        beneficiary = _beneficiary;\n' +
      '        token = _token;\n' +
      '        totalAmount = _totalAmount;\n' +
      '        start = _start;\n' +
      '        cliff = _cliff;\n' +
      '        duration = _duration;\n' +
      '    }\n\n' +
      '    function releasable() public view returns (uint256) {\n' +
      '        if (block.timestamp < start + cliff) return 0;\n' +
      '        if (block.timestamp >= start + duration) return totalAmount - released;\n' +
      '        return (totalAmount * (block.timestamp - start)) / duration - released;\n' +
      '    }\n\n' +
      '    function release() external {\n' +
      '        uint256 amt = releasable();\n' +
      '        require(amt > 0, "nothing releasable");\n' +
      '        released += amt;\n' +
      '        emit Released(beneficiary, amt);\n' +
      '        // NOTE: token transfer must be wired with a real token interface.\n' +
      '    }\n\n' +
      (spec.revocable ? '    function revoke() external onlyOwner { revoked = true; emit Revoked(); }\n\n' : '') +
      '}\n';
  }

  function _treasurySource(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    address public owner;\n' +
      '    uint256 public spendingLimit;\n' +
      '    mapping(address => bool) public approvers;\n' +
      '    mapping(address => bool) public supportedAssets;\n\n' +
      '    event Withdrawn(address indexed to, uint256 amount);\n' +
      '    event AssetAdded(address indexed asset);\n\n' +
      '    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }\n' +
      '    modifier onlyApprover() { require(msg.sender == owner || approvers[msg.sender], "not approver"); _; }\n\n' +
      '    constructor(uint256 _spendingLimit) {\n' +
      '        owner = msg.sender;\n' +
      '        spendingLimit = _spendingLimit;\n' +
      '    }\n\n' +
      '    function addApprover(address a) external onlyOwner { approvers[a] = true; }\n' +
      '    function removeApprover(address a) external onlyOwner { approvers[a] = false; }\n' +
      '    function addAsset(address asset) external onlyOwner { supportedAssets[asset] = true; emit AssetAdded(asset); }\n' +
      '    function setSpendingLimit(uint256 limit) external onlyOwner { spendingLimit = limit; }\n' +
      '    function transferOwnership(address newOwner) external onlyOwner { require(newOwner != address(0), "zero address"); owner = newOwner; }\n\n' +
      '    function withdraw(address to, uint256 amount) external onlyApprover {\n' +
      '        require(amount <= spendingLimit, "over limit");\n' +
      '        require(to != address(0), "zero address");\n' +
      '        payable(to).transfer(amount);\n' +
      '        emit Withdrawn(to, amount);\n' +
      '    }\n' +
      '}\n';
  }

  function _timelockSource(spec) {
    var N = esc(spec.name);
    return '// SPDX-License-Identifier: MIT\n' +
      'pragma solidity ^' + SOLIDITY_VERSION + ';\n\n' +
      'contract ' + N + ' {\n' +
      '    address public admin;\n' +
      '    uint256 public minDelay;\n' +
      '    mapping(address => bool) public proposers;\n' +
      '    mapping(address => bool) public executors;\n' +
      '    mapping(bytes32 => uint256) public scheduled;\n\n' +
      '    event Scheduled(bytes32 indexed id, uint256 eta);\n' +
      '    event Executed(bytes32 indexed id);\n' +
      '    event Cancelled(bytes32 indexed id);\n\n' +
      '    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }\n\n' +
      '    constructor(uint256 _minDelay) {\n' +
      '        admin = msg.sender;\n' +
      '        minDelay = _minDelay;\n' +
      '        proposers[msg.sender] = true;\n' +
      '        executors[msg.sender] = true;\n' +
      '    }\n\n' +
      '    function setProposer(address who, bool ok) external onlyAdmin { proposers[who] = ok; }\n' +
      '    function setExecutor(address who, bool ok) external onlyAdmin { executors[who] = ok; }\n' +
      '    function setMinDelay(uint256 delay) external onlyAdmin { minDelay = delay; }\n\n' +
      '    function schedule(bytes32 id, uint256 delay) external {\n' +
      '        require(proposers[msg.sender], "not proposer");\n' +
      '        require(delay >= minDelay, "delay too short");\n' +
      '        scheduled[id] = block.timestamp + delay;\n' +
      '        emit Scheduled(id, scheduled[id]);\n' +
      '    }\n\n' +
      '    function execute(bytes32 id) external {\n' +
      '        require(executors[msg.sender], "not executor");\n' +
      '        require(scheduled[id] != 0 && block.timestamp >= scheduled[id], "not ready");\n' +
      '        delete scheduled[id];\n' +
      '        emit Executed(id);\n' +
      '    }\n\n' +
      (spec.cancellable !== false ? '    function cancel(bytes32 id) external onlyAdmin {\n        delete scheduled[id];\n        emit Cancelled(id);\n    }\n\n' : '') +
      '}\n';
  }

  // ── GenLayer (Python) templates ────────────────────────────────────────────
  function _genlayerIntelligentSource(spec) {
    var N = spec.name || 'Counter';
    return '# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }\n\n' +
      'from genlayer import *\n\n\n' +
      'class ' + esc(N) + '(gl.Contract):\n' +
      '    """' + String(spec.description || '').replace(/"/g, '') + '"""\n\n' +
      '    counter: int\n' +
      '    owner: str\n\n' +
      '    def __init__(self):\n' +
      '        self.counter = 0\n' +
      '        self.owner = gl.message.sender_address.as_hex\n\n' +
      '    @gl.public.write\n' +
      '    def increment(self) -> None:\n' +
      '        self.counter += 1\n\n' +
      '    @gl.public.write\n' +
      '    def set_value(self, value: int) -> None:\n' +
      '        assert gl.message.sender_address.as_hex == self.owner, "only owner"\n' +
      '        self.counter = value\n\n' +
      '    @gl.public.view\n' +
      '    def get_value(self) -> int:\n' +
      '        return self.counter\n';
  }

  function _genlayerAISource(spec) {
    var N = spec.name || 'AIDecision';
    return '# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }\n\n' +
      'from genlayer import *\n\n\n' +
      'class ' + esc(N) + '(gl.Contract):\n' +
      '    """' + String(spec.description || '').replace(/"/g, '') + '"""\n\n' +
      '    results: TreeMap[str, str]\n\n' +
      '    def __init__(self):\n' +
      '        self.results = TreeMap[str, str]()\n\n' +
      '    @gl.public.write\n' +
      '    def decide(self, subject: str, context: str) -> str:\n' +
      '        def get_input() -> str:\n' +
      '            return context\n' +
      '        decision: str = gl.eq_principle.prompt_non_comparative(\n' +
      '            get_input,\n' +
      '            task="Analyze the provided context and return a concise decision.",\n' +
      '            criteria="The decision is grounded in the context and does not invent facts."\n' +
      '        )\n' +
      '        self.results[subject] = decision\n' +
      '        return decision\n\n' +
      '    @gl.public.view\n' +
      '    def get_result(self, subject: str) -> str:\n' +
      '        return self.results.get(subject, "")\n';
  }

  function generateSource(spec) {
    spec = spec || {};
    switch (spec.type) {
      case 'erc20': return _erc20Source(spec);
      case 'erc721': return _erc721Source(spec);
      case 'erc1155': return _erc1155Source(spec);
      case 'escrow': return _escrowSource(spec);
      case 'staking': return _stakingSource(spec);
      case 'vesting': return _vestingSource(spec);
      case 'treasury': return _treasurySource(spec);
      case 'timelock': return _timelockSource(spec);
      case 'custom': return String(spec.source || '');
      case 'genlayer_intelligent': return _genlayerIntelligentSource(spec);
      case 'genlayer_ai': return _genlayerAISource(spec);
      case 'genlayer_custom': return String(spec.source || '');
      default: return '';
    }
  }

  // ── Constructor arguments ──────────────────────────────────────────────────
  function constructorArgs(spec) {
    spec = spec || {};
    switch (spec.type) {
      case 'erc20': {
        var big = (spec.supply || 0).toString() + '0'.repeat(18);
        return [{ name: 'initialSupply', type: 'uint256', value: big, label: 'Initial supply (wei, 18 decimals)' }];
      }
      case 'escrow':
        return [
          { name: '_seller', type: 'address', value: spec.seller || '', label: 'Seller address' },
          { name: '_arbiter', type: 'address', value: spec.arbiter || '', label: 'Arbiter address' },
          { name: '_amount', type: 'uint256', value: String(spec.amount || '0'), label: 'Escrow amount' },
          { name: '_timeout', type: 'uint256', value: String(spec.timeout || '0'), label: 'Timeout (seconds)' }
        ];
      case 'staking':
        return [
          { name: '_stakeToken', type: 'address', value: spec.stakeToken || '', label: 'Stake token address' },
          { name: '_rewardToken', type: 'address', value: spec.rewardToken || '', label: 'Reward token address' },
          { name: '_lockPeriod', type: 'uint256', value: String(spec.lockPeriod || '0'), label: 'Lock period (seconds)' },
          { name: '_rewardRate', type: 'uint256', value: '0', label: 'Reward rate (must be configured)' }
        ];
      case 'vesting':
        return [
          { name: '_beneficiary', type: 'address', value: spec.beneficiary || '', label: 'Beneficiary address' },
          { name: '_token', type: 'address', value: spec.token || '', label: 'Token address' },
          { name: '_totalAmount', type: 'uint256', value: String(spec.totalAmount || '0'), label: 'Total amount' },
          { name: '_start', type: 'uint256', value: String(spec.start || '0'), label: 'Start timestamp' },
          { name: '_cliff', type: 'uint256', value: String(spec.cliff || '0'), label: 'Cliff (seconds)' },
          { name: '_duration', type: 'uint256', value: String(spec.duration || '0'), label: 'Duration (seconds)' }
        ];
      case 'treasury':
        return [{ name: '_spendingLimit', type: 'uint256', value: String(spec.spendingLimit || '0'), label: 'Spending limit' }];
      case 'timelock':
        return [{ name: '_minDelay', type: 'uint256', value: String(spec.minDelay || '86400'), label: 'Minimum delay (seconds)' }];
      default:
        return [];
    }
  }

  // ── Deployment capability (honest) ─────────────────────────────────────────
  // Returns { supported, reason }. Never claims a transport that isn't wired.
  //   EVM (Solidity) contracts: no compiler + no EVM deployer in this project.
  //   GENLAYER contracts: deployable on GenLayer networks via the GenLayer SDK.
  function deploymentCapability(spec, networkFamily) {
    spec = spec || {};
    var type = CONTRACT_TYPES[spec.type];
    if (!type) return { supported: false, reason: 'NOT_SUPPORTED: unknown contract type' };
    var isGenLayerNetwork = networkFamily === 'GENLAYER';

    if (type.family === 'GENLAYER') {
      if (isGenLayerNetwork) return { supported: true, reason: 'GenLayer Intelligent Contract via the GenLayer SDK' };
      return { supported: false, reason: 'NOT_SUPPORTED: GenLayer contracts only deploy on GenLayer networks (Studionet/Bradbury)' };
    }
    // EVM family
    if (isGenLayerNetwork) {
      return { supported: false, reason: 'NOT_SUPPORTED: GenLayer deploys GenLayer (Python) intelligent contracts, not Solidity' };
    }
    return { supported: false, reason: 'NOT_SUPPORTED: no EVM/Solidity deployment transport is wired in this project (no compiler, no EVM deployer). Copy the Solidity and deploy via Remix/Hardhat/Foundry.' };
  }

  return {
    BUILDER_VERSION: BUILDER_VERSION,
    SOLIDITY_VERSION: SOLIDITY_VERSION,
    CONTRACT_TYPES: CONTRACT_TYPES,
    EVM_TYPES: EVM_TYPES,
    GENLAYER_TYPES: GENLAYER_TYPES,
    getType: getType,
    allTypes: allTypes,
    fnv1a: fnv1a,
    specHash: specHash,
    sourceHash: sourceHash,
    defaultSpec: defaultSpec,
    validateSpec: validateSpec,
    generateSource: generateSource,
    constructorArgs: constructorArgs,
    deploymentCapability: deploymentCapability,
    esc: esc
  };
});
