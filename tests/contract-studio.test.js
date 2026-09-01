'use strict';
// Phase 7.2 tests: Contract Studio 2.0 (templates, security review, capability).
// Run with:  node tests/contract-studio.test.js
const test = require('node:test');
const assert = require('node:assert');
const Templates = require('../public/contract-templates.js');
const Security = require('../public/contract-security.js');
const Studio = require('../public/contract-studio.js');

function buildSpec(spec) {
  return Object.assign({}, Templates.defaultSpec(spec.type), spec);
}

// ── Catalog / determinism ────────────────────────────────────────────────────

test('catalog: 8 EVM types + 3 GenLayer types', function () {
  assert.deepEqual(Templates.EVM_TYPES.sort(), ['custom','erc1155','erc20','erc721','escrow','staking','timelock','treasury','vesting'].sort());
  assert.deepEqual(Templates.GENLAYER_TYPES.sort(), ['genlayer_ai','genlayer_custom','genlayer_intelligent'].sort());
  assert.equal(Templates.BUILDER_VERSION, '2.0.0');
});

test('generation is deterministic with stable specHash + sourceHash', function () {
  var s1 = buildSpec({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 });
  var a = Templates.generateSource(s1);
  var b = Templates.generateSource(buildSpec({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 }));
  assert.equal(a, b);
  assert.equal(Templates.specHash(s1), Templates.specHash(buildSpec({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 })));
  assert.equal(Templates.sourceHash(a), Templates.sourceHash(b));
});

// ── ERC-20 fixes ─────────────────────────────────────────────────────────────

test('ERC-20 "no privileged administration" generates NO owner / onlyOwner', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100, accessControl: 'none' }));
  assert.ok(src.indexOf('address public owner') === -1, 'no dead ownership storage');
  assert.ok(src.indexOf('onlyOwner') === -1, 'no dead modifier');
  assert.ok(src.indexOf('function transferOwnership') === -1, 'no ownership transfer fn');
});

test('ERC-20 Ownable generates coherent ownership', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100, accessControl: 'ownable' }));
  assert.ok(src.indexOf('onlyOwner') !== -1);
  assert.ok(src.indexOf('transferOwnership') !== -1);
  assert.ok(src.indexOf('owner = msg.sender') !== -1);
});

test('ERC-20 AccessControl generates role structure', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100, accessControl: 'accesscontrol' }));
  assert.ok(src.indexOf('DEFAULT_ADMIN_ROLE') !== -1);
  assert.ok(src.indexOf('MINTER_ROLE') !== -1);
  assert.ok(src.indexOf('grantRole') !== -1);
});

test('ERC-20 transferFrom has zero-address, balance, allowance checks + bool return', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100, accessControl: 'none' }));
  var tf = src.split('function transferFrom')[1].split('function increaseAllowance')[0];
  assert.ok(tf.indexOf('zero address') !== -1);
  assert.ok(tf.indexOf('insufficient balance') !== -1);
  assert.ok(tf.indexOf('insufficient allowance') !== -1);
  assert.ok(tf.indexOf('return true') !== -1);
  assert.ok(tf.indexOf('emit Transfer') !== -1);
  // transfer() also has zero-address check (consistency)
  var tr = src.split('function transfer(')[1].split('function approve')[0];
  assert.ok(tr.indexOf('zero address') !== -1);
});

test('ERC-20 includes increaseAllowance / decreaseAllowance helpers', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100 }));
  assert.ok(src.indexOf('increaseAllowance') !== -1);
  assert.ok(src.indexOf('decreaseAllowance') !== -1);
});

test('ERC-20 mintable has access-controlled mint; fixed has no mint', function () {
  var mintable = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100, supplyType: 'mintable', accessControl: 'ownable' }));
  assert.ok(/\bfunction mint\s*\(/.test(mintable));
  assert.ok(mintable.indexOf('onlyOwner') !== -1);
  var fixed = Templates.generateSource(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 100, supplyType: 'fixed' }));
  assert.ok(!/\bfunction mint\s*\(/.test(fixed));
});

// ── Validation / unsupported options ─────────────────────────────────────────

test('validateSpec rejects NOT_IMPLEMENTED options (permit/votes/fee)', function () {
  var v = Templates.validateSpec(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 1, permit: true }));
  assert.equal(v.valid, false);
  assert.ok(v.errors.some(function (e) { return e.indexOf('NOT_IMPLEMENTED') !== -1; }));
  var v2 = Templates.validateSpec(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 1, votes: true }));
  assert.equal(v2.valid, false);
  var v3 = Templates.validateSpec(buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 1, fee: 'custom' }));
  assert.equal(v3.valid, false);
});

test('validateSpec rejects unconfigured staking reward model', function () {
  var v = Templates.validateSpec(buildSpec({ type: 'staking', name: 'S' }));
  assert.equal(v.valid, false);
  assert.ok(v.errors.some(function (e) { return e.indexOf('reward model') !== -1; }));
  var ok = Templates.validateSpec(buildSpec({ type: 'staking', name: 'S', rewardModel: 'fixed-rate' }));
  assert.equal(ok.valid, true);
});

test('validateSpec requires source for custom types', function () {
  assert.equal(Templates.validateSpec(buildSpec({ type: 'custom', name: 'C', source: '' })).valid, false);
  assert.equal(Templates.validateSpec(buildSpec({ type: 'custom', name: 'C', source: 'pragma solidity ^0.8.0; contract C {}' })).valid, true);
  assert.equal(Templates.validateSpec(buildSpec({ type: 'genlayer_custom', name: 'C', source: '' })).valid, false);
});

// ── Other templates ──────────────────────────────────────────────────────────

test('ERC-721 template generates mint/ownerOf/transferFrom/approvals', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc721', name: 'N', symbol: 'N', accessControl: 'ownable' }));
  assert.ok(/\bfunction mint\s*\(/.test(src));
  assert.ok(/\bfunction ownerOf\s*\(/.test(src));
  assert.ok(/\bfunction transferFrom\s*\(/.test(src));
  assert.ok(/\bfunction setApprovalForAll\s*\(/.test(src));
});

test('ERC-1155 template generates mint/balanceOf/safeTransferFrom', function () {
  var src = Templates.generateSource(buildSpec({ type: 'erc1155', name: 'M', accessControl: 'ownable' }));
  assert.ok(/\bfunction mint\s*\(/.test(src));
  assert.ok(/\bfunction balanceOf\s*\(/.test(src));
  assert.ok(/\bfunction safeTransferFrom\s*\(/.test(src));
});

test('Escrow template has state machine + double release/refund guards', function () {
  var src = Templates.generateSource(buildSpec({ type: 'escrow', name: 'E', assetType: 'native' }));
  assert.ok(src.indexOf('CREATED') !== -1 && src.indexOf('FUNDED') !== -1 && src.indexOf('RELEASED') !== -1 && src.indexOf('REFUNDED') !== -1 && src.indexOf('DISPUTED') !== -1);
  var rel = src.split('function release()')[1].split('function refund()')[0];
  assert.ok(rel.indexOf('require(state == State.FUNDED') !== -1);
  assert.ok(rel.indexOf('state = State.RELEASED') !== -1);
});

test('Vesting / Treasury / Timelock templates generate', function () {
  assert.ok(/\bfunction release\s*\(/.test(Templates.generateSource(buildSpec({ type: 'vesting', name: 'V' }))));
  assert.ok(/\bfunction withdraw\s*\(/.test(Templates.generateSource(buildSpec({ type: 'treasury', name: 'T' }))));
  assert.ok(/\bfunction schedule\s*\(/.test(Templates.generateSource(buildSpec({ type: 'timelock', name: 'TL' }))));
});

test('GenLayer templates are Python gl.Contract', function () {
  var src = Templates.generateSource(buildSpec({ type: 'genlayer_intelligent', name: 'Counter' }));
  assert.ok(src.indexOf('gl.Contract') !== -1);
  assert.ok(src.indexOf('@gl.public.write') !== -1);
  var ai = Templates.generateSource(buildSpec({ type: 'genlayer_ai', name: 'AIDecision' }));
  assert.ok(ai.indexOf('eq_principle') !== -1);
});

// ── Deployment capability (honest) ───────────────────────────────────────────

test('deploymentCapability: EVM contract on EVM network => NOT_SUPPORTED (no transport)', function () {
  var c = Templates.deploymentCapability({ type: 'erc20' }, 'EVM');
  assert.equal(c.supported, false);
  assert.ok(c.reason.indexOf('NOT_SUPPORTED') !== -1);
});

test('deploymentCapability: EVM contract on GenLayer network => NOT_SUPPORTED', function () {
  assert.equal(Templates.deploymentCapability({ type: 'erc20' }, 'GENLAYER').supported, false);
});

test('deploymentCapability: GenLayer contract on GenLayer network => supported', function () {
  var c = Templates.deploymentCapability({ type: 'genlayer_intelligent' }, 'GENLAYER');
  assert.equal(c.supported, true);
});

test('deploymentCapability: GenLayer contract on EVM network => NOT_SUPPORTED', function () {
  assert.equal(Templates.deploymentCapability({ type: 'genlayer_intelligent' }, 'EVM').supported, false);
});

// ── Constructor arguments ────────────────────────────────────────────────────

test('constructorArgs for ERC-20 is deterministic wei string', function () {
  var a = Templates.constructorArgs(buildSpec({ type: 'erc20', supply: 1000000 }));
  assert.equal(a[0].name, 'initialSupply');
  assert.equal(a[0].value, '1000000000000000000000000');
});

test('constructorArgs for escrow includes seller/arbiter/amount/timeout', function () {
  var a = Templates.constructorArgs(buildSpec({ type: 'escrow' }));
  assert.deepEqual(a.map(function (x) { return x.name; }), ['_seller', '_arbiter', '_amount', '_timeout']);
});

// ── Security review ──────────────────────────────────────────────────────────

test('security review: fixed supply / no admin / no upgrade => READY_FOR_DEPLOYMENT', function () {
  var spec = buildSpec({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000, supplyType: 'fixed', accessControl: 'none' });
  var src = Templates.generateSource(spec);
  var r = Security.review(spec, src);
  assert.equal(r.reviewStatus, 'READY_FOR_DEPLOYMENT');
  assert.ok(r.categories.accessControl.text.indexOf('No privileged administration') !== -1);
  assert.ok(r.categories.upgradeability.text.indexOf('No upgrade mechanism') !== -1);
  assert.ok(r.categories.externalCalls.text.indexOf('No external calls') !== -1);
});

test('security review: mintable raises a MEDIUM warning (not a false vulnerability)', function () {
  var spec = buildSpec({ type: 'erc20', name: 'T', symbol: 'T', supply: 1, supplyType: 'mintable', accessControl: 'ownable' });
  var r = Security.review(spec, Templates.generateSource(spec));
  assert.ok(r.warnings.some(function (w) { return w.level === 'MEDIUM' && w.text.toLowerCase().indexOf('mintable') !== -1; }));
});

test('security review: delegatecall/selfdestruct flagged', function () {
  var r = Security.review({ type: 'custom', family: 'EVM' }, 'pragma solidity ^0.8.0; contract X { function kill() { selfdestruct(payable(msg.sender)); } }');
  assert.ok(r.warnings.some(function (w) { return w.level === 'HIGH'; }));
});

test('security review: GenLayer family is not reviewed as EVM', function () {
  var src = Templates.generateSource(buildSpec({ type: 'genlayer_intelligent', name: 'Counter' }));
  var r = Security.review({ type: 'genlayer_intelligent', family: 'GENLAYER' }, src);
  assert.equal(r.family, 'GENLAYER');
});

// ── Studio orchestration ─────────────────────────────────────────────────────

test('studio build produces source + review + hashes', function () {
  var r = Studio.build({ type: 'erc20', name: 'MyToken', symbol: 'MTK', supply: 1000000 });
  assert.equal(r.ok, true);
  assert.ok(r.source.indexOf('contract MyToken') !== -1);
  assert.ok(r.review);
  assert.equal(r.hashes.contractType, 'erc20');
  assert.equal(r.hashes.builderVersion, '2.0.0');
  assert.ok(r.hashes.specHash && r.hashes.sourceHash);
});

test('studio build rejects invalid spec', function () {
  var r = Studio.build({ type: 'erc20', name: 'T', symbol: 'T', supply: 1, permit: true });
  assert.equal(r.ok, false);
  assert.ok(r.validation.errors.some(function (e) { return e.indexOf('NOT_IMPLEMENTED') !== -1; }));
});

test('studio detectCreateType maps chat text to types', function () {
  assert.equal(Studio.detectCreateType('create an erc20 token'), 'erc20');
  assert.equal(Studio.detectCreateType('create an NFT'), 'erc721');
  assert.equal(Studio.detectCreateType('create escrow'), 'escrow');
  assert.equal(Studio.detectCreateType('create staking contract'), 'staking');
  assert.equal(Studio.detectCreateType('create vesting'), 'vesting');
  assert.equal(Studio.detectCreateType('create treasury'), 'treasury');
  assert.equal(Studio.detectCreateType('create timelock'), 'timelock');
  assert.equal(Studio.detectCreateType('create a GenLayer contract'), 'genlayer_intelligent');
});

test('studio guidedQuestions only asks necessary params per type', function () {
  assert.ok(Studio.guidedQuestions('erc20').length >= 5);
  assert.ok(Studio.guidedQuestions('timelock').length <= 2);
  assert.equal(Studio.guidedQuestions('custom').length, 0);
});

test('capabilityFor returns NOT_SUPPORTED for EVM contracts', function () {
  var b = Studio.build({ type: 'erc20', name: 'T', symbol: 'T', supply: 1 });
  var c = Studio.capabilityFor(b, { id: 'ethereum', family: 'EVM' });
  assert.equal(c.supported, false);
  var gl = Studio.build({ type: 'genlayer_intelligent', name: 'Counter' });
  var cg = Studio.capabilityFor(gl, { id: 'genlayerStudionet', family: 'GENLAYER' });
  assert.equal(cg.supported, true);
});

console.log('\nAll contract-studio tests completed.');
