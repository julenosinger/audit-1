'use strict';
// Phase 7.5 tests: intelligence unification + security hardening invariants.
// Run with:  node tests/phase75-security.test.js
const test = require('node:test');
const assert = require('node:assert');
const Router = require('../public/intent-router.js');
const Networks = require('../public/networks.js');

// ── Unified intent classification (Chat == Quick Action) ────────────────────

test('chat phrases classify to the 6 real intents', function () {
  assert.equal(Router.detectIntent('audit contract', false), 'AUDIT_CONTRACT');
  assert.equal(Router.detectIntent('create contract', false), 'CREATE_CONTRACT');
  assert.equal(Router.detectIntent('my portfolio', false), 'VIEW_PORTFOLIO');
  assert.equal(Router.detectIntent('check approvals', false), 'CHECK_APPROVALS');
  assert.equal(Router.detectIntent('explain findings', false), 'EXPLAIN_FINDINGS');
  assert.equal(Router.detectIntent('safe to approve', false), 'ASSESS_APPROVAL');
});

test('quick-action labels converge on the same intents as the chat', function () {
  // Quick actions dispatch by id; the same detection applies to equivalent chat text.
  assert.equal(Router.detectIntent('Audit Contract'), Router.detectIntent('audit contract'));
  assert.equal(Router.detectIntent('Create Contract'), Router.detectIntent('create contract'));
  assert.equal(Router.detectIntent('My Portfolio'), Router.detectIntent('my portfolio'));
  assert.equal(Router.detectIntent('Check Approvals'), Router.detectIntent('check approvals'));
  assert.equal(Router.detectIntent('Explain Findings'), Router.detectIntent('explain findings'));
  assert.equal(Router.detectIntent('Safe to Approve?'), Router.detectIntent('safe to approve'));
});

// ── No Ethereum default / fallback ───────────────────────────────────────────

test('network registry default is GenLayer Studionet (no Ethereum default)', function () {
  assert.equal(Networks.DEFAULT_NETWORK_ID, 'genlayerStudionet');
});

test('unknown network is UNKNOWN, never silently Ethereum', function () {
  assert.equal(Router.networkFamily(null), 'UNKNOWN');
  assert.equal(Router.networkFamily(undefined), 'UNKNOWN');
  assert.equal(Networks.getFamily('does-not-exist'), 'UNKNOWN');
});

// ── No signing / no write in quick actions ───────────────────────────────────

test('no quick-action intent requires a signature or a write transaction', function () {
  Object.keys(Router.INTENTS).forEach(function (k) {
    var c = Router.capability(Router.INTENTS[k]);
    assert.equal(c.write, false, k + ' must be write=false');
    assert.ok(!('signature' in c) || c.signature === false, k + ' must not sign');
  });
});

test('Audit / Create / Explain require NO wallet', function () {
  ['AUDIT_CONTRACT', 'CREATE_CONTRACT', 'EXPLAIN_FINDINGS'].forEach(function (i) {
    assert.equal(Router.capability(i).wallet, false);
  });
});

// ── GenLayer audit never uses eth_getCode (routing) ─────────────────────────

test('planAudit routes a GenLayer deployment to genlayer mode (NOT evm/discover)', function () {
  var ctx = Router.buildContext({ lastDeployment: { address: '0xDEF', network: 'GenLayer Studionet', networkId: 'genlayerStudionet' } });
  var plan = Router.planAudit(ctx);
  assert.equal(plan.mode, 'genlayer');
  assert.notEqual(plan.mode, 'evm');
  assert.notEqual(plan.mode, 'discover');
});

test('planAudit without deployment and without last audit => needs_input', function () {
  assert.equal(Router.planAudit(Router.buildContext({})).mode, 'needs_input');
});

// ── nextActions never suggests unsupported operations ───────────────────────

test('nextActions after deployment suggests only real actions', function () {
  var acts = Router.nextActions(Router.buildContext({ lastDeployment: { address: '0xDEF', txHash: '0xH' } }));
  var ids = acts.map(function (a) { return a.id; });
  assert.ok(ids.indexOf('audit_contract') !== -1);
  assert.ok(ids.indexOf('view_tx') !== -1);
  // Never suggests deployment/write actions from an audit context.
  assert.ok(ids.indexOf('deploy') === -1);
});

test('nextActions after audit suggests explain (never fabricated data)', function () {
  var acts = Router.nextActions(Router.buildContext({ lastAuditResult: { findings: [] } }));
  assert.ok(acts.some(function (a) { return a.id === 'explain_findings'; }));
});

// ── UNKNOWN is never SAFE (honesty invariants) ──────────────────────────────

test('buildContext never fabricates values (null / unknown default)', function () {
  var ctx = Router.buildContext({});
  assert.equal(ctx.lastAudit, null);
  assert.equal(ctx.lastDeployment, null);
  assert.equal(ctx.lastFindings, null);
  assert.equal(ctx.wallet.address, null);
  assert.equal(ctx.wallet.connected, false);
});

console.log('\nAll phase75-security tests completed.');
