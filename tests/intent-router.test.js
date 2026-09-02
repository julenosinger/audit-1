'use strict';
// Phase 7.4 tests: Intent Router + Context Engine + capability/network policy.
// Run with:  node tests/intent-router.test.js
const test = require('node:test');
const assert = require('node:assert');
const Router = require('../public/intent-router.js');
const Networks = require('../public/networks.js');

// ── Intents ──────────────────────────────────────────────────────────────────

test('detectIntent: AUDIT_CONTRACT for addresses and audit verbs', function () {
  assert.equal(Router.detectIntent('Audit 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 on Ethereum'), 'AUDIT_CONTRACT');
  assert.equal(Router.detectIntent('audit this contract', false), 'AUDIT_CONTRACT');
  assert.equal(Router.detectIntent('scan 0xabc', false), 'AUDIT_CONTRACT');
});

test('detectIntent: CREATE_CONTRACT for create/build verbs + contract words', function () {
  assert.equal(Router.detectIntent('create an ERC-20 token', false), 'CREATE_CONTRACT');
  assert.equal(Router.detectIntent('build an escrow contract', false), 'CREATE_CONTRACT');
  assert.equal(Router.detectIntent('create a GenLayer intelligent contract', false), 'CREATE_CONTRACT');
});

test('detectIntent: VIEW_PORTFOLIO / CHECK_APPROVALS / EXPLAIN_FINDINGS / ASSESS_APPROVAL', function () {
  assert.equal(Router.detectIntent('scan my portfolio', false), 'VIEW_PORTFOLIO');
  assert.equal(Router.detectIntent('check my approvals', false), 'CHECK_APPROVALS');
  assert.equal(Router.detectIntent('explain the last finding', false), 'EXPLAIN_FINDINGS');
  assert.equal(Router.detectIntent('is it safe to approve this?', false), 'ASSESS_APPROVAL');
});

// ── Network family ───────────────────────────────────────────────────────────

test('networkFamily: GenLayer vs EVM vs UNKNOWN', function () {
  assert.equal(Router.networkFamily('genlayerStudionet'), 'GENLAYER');
  assert.equal(Router.networkFamily('genlayerBradbury'), 'GENLAYER');
  assert.equal(Router.networkFamily('studionet'), 'GENLAYER');
  assert.equal(Router.networkFamily('ethereum'), 'EVM');
  assert.equal(Router.networkFamily('bsc'), 'EVM');
  assert.equal(Router.networkFamily('base'), 'EVM');
  assert.equal(Router.networkFamily('arbitrum'), 'EVM');
  assert.equal(Router.networkFamily('optimism'), 'EVM');
  assert.equal(Router.networkFamily(null), 'UNKNOWN');
});

test('isGenLayerNetwork distinguishes the transaction networks', function () {
  assert.equal(Router.isGenLayerNetwork('genlayerStudionet'), true);
  assert.equal(Router.isGenLayerNetwork('ethereum'), false);
});

test('networks.getFamily matches the intent router family model', function () {
  assert.equal(Networks.getFamily('genlayerStudionet'), 'GENLAYER');
  assert.equal(Networks.getFamily('ethereum'), 'EVM');
  assert.equal(Networks.getFamily('bogus'), 'UNKNOWN');
});

// ── Capability matrix (wallet / read / write / network) ──────────────────────

test('capability: Audit Contract is read-only and requires no wallet', function () {
  var c = Router.capability(Router.INTENTS.AUDIT_CONTRACT);
  assert.equal(c.wallet, false);
  assert.equal(c.write, false);
  assert.equal(c.read, true);
});

test('capability: Create Contract requires no wallet (deploy is a separate step)', function () {
  var c = Router.capability(Router.INTENTS.CREATE_CONTRACT);
  assert.equal(c.wallet, false);
  assert.equal(c.write, false);
});

test('capability: Portfolio / Approvals / Assess are conditional-wallet and read-only', function () {
  ['VIEW_PORTFOLIO', 'CHECK_APPROVALS', 'ASSESS_APPROVAL'].forEach(function (i) {
    var c = Router.capability(i);
    assert.equal(c.wallet, 'conditional');
    assert.equal(c.write, false);
    assert.equal(c.read, true);
  });
});

test('capability: Explain Findings requires no wallet', function () {
  var c = Router.capability(Router.INTENTS.EXPLAIN_FINDINGS);
  assert.equal(c.wallet, false);
  assert.equal(c.write, false);
});

// ── Context Engine ───────────────────────────────────────────────────────────

test('buildContext: unknown fields stay null (never fabricated)', function () {
  var ctx = Router.buildContext({});
  assert.equal(ctx.wallet.connected, false);
  assert.equal(ctx.wallet.address, null);
  assert.equal(ctx.lastAudit, null);
  assert.equal(ctx.lastDeployment, null);
  assert.equal(ctx.lastFindings, null);
  assert.equal(ctx.network.transaction, 'studionet');
  assert.equal(ctx.network.deployment, 'studionet');
});

test('buildContext: carries real state through', function () {
  var ctx = Router.buildContext({
    walletAddress: '0xABC', walletChainId: 61999,
    lastAuditResult: { findings: [{ id: 'x' }] },
    lastDeployment: { address: '0xDEF' }
  });
  assert.equal(ctx.wallet.connected, true);
  assert.equal(ctx.wallet.address, '0xABC');
  assert.equal(ctx.lastFindings.length, 1);
  assert.equal(ctx.lastDeployment.address, '0xDEF');
});

// ── Critical GenLayer audit routing ──────────────────────────────────────────

test('planAudit: GenLayer deployment routes to genlayer mode (NOT eth_getCode)', function () {
  var ctx = Router.buildContext({ lastDeployment: { address: '0xDEF', network: 'GenLayer Studionet', networkId: 'genlayerStudionet' } });
  var plan = Router.planAudit(ctx);
  assert.equal(plan.mode, 'genlayer');
  assert.equal(plan.address, '0xDEF');
});

test('planAudit: no deployment and no last audit => needs_input', function () {
  var plan = Router.planAudit(Router.buildContext({}));
  assert.equal(plan.mode, 'needs_input');
});

test('planAudit: last audit address (EVM) routes to discover (never assumes)', function () {
  var plan = Router.planAudit(Router.buildContext({ lastAuditAddress: '0xABC' }));
  assert.equal(plan.mode, 'discover');
  assert.equal(plan.address, '0xABC');
});

// ── Next best action ─────────────────────────────────────────────────────────

test('nextActions: after deployment suggests Audit Contract (never unsupported ops)', function () {
  var ctx = Router.buildContext({ lastDeployment: { address: '0xDEF', txHash: '0xHASH' } });
  var acts = Router.nextActions(ctx);
  assert.ok(acts.some(function (a) { return a.id === 'audit_contract'; }));
  assert.ok(acts.some(function (a) { return a.id === 'view_tx'; }));
});

test('nextActions: after audit suggests Explain Findings', function () {
  var ctx = Router.buildContext({ lastAuditResult: { findings: [] } });
  var acts = Router.nextActions(ctx);
  assert.ok(acts.some(function (a) { return a.id === 'explain_findings'; }));
});

console.log('\nAll intent-router tests completed.');
