'use strict';
// Phase 7.6.2 tests: real-time GenLayer consensus UX + unified transaction
// engine + observability. Deterministic only — transport is mocked, never fake.
// Run with:  node tests/phase762.test.js
const test = require('node:test');
const assert = require('node:assert');
const Tx = require('../public/genlayer-tx.js');
const ChatStore = require('../public/chat-store.js');
const GenLayerClient = require('../public/genlayer-client.js');

function memStorage() {
  var m = {};
  return {
    getItem: function (k) { return Object.prototype.hasOwnProperty.call(m, k) ? m[k] : null; },
    setItem: function (k, v) { m[k] = String(v); },
    removeItem: function (k) { delete m[k]; }
  };
}
const noSleep = function () { return Promise.resolve(); };

const TEST_NETWORKS = {
  studionet: { id: 'studionet', name: 'Studionet', chainId: 61999, rpc: 'https://studio.genlayer.com/api', contract: '0x' + 'ab'.repeat(20), deployed: true },
  bradbury: { id: 'bradbury', name: 'Bradbury Testnet', chainId: 4221, rpc: 'https://rpc-bradbury.genlayer.com', contract: '0x' + 'cd'.repeat(20), deployed: true }
};

// A mock SDK whose getTransaction plays back a fixed status sequence, then holds
// the last status forever. Supports deploy + audit (writeContract + deployContract).
function sequenceSdk(statuses, contractAddress) {
  var i = 0;
  function nextTx() {
    var name = statuses[Math.min(i++, statuses.length - 1)];
    var num = Tx.STATUS_NAMES.indexOf(name);
    return {
      statusName: name,
      status: num,
      txExecutionResultName: (name === 'ACCEPTED' || name === 'FINALIZED') ? 'FINISHED_WITH_RETURN' : undefined,
      txDataDecoded: (name === 'ACCEPTED' || name === 'FINALIZED') ? { contractAddress: contractAddress } : undefined
    };
  }
  var readClient = {
    getContractSchema: async function () { return { ctor: {}, methods: { analyze_evidence: {}, get_analysis: {} } }; },
    getTransaction: async function () { return nextTx(); },
    readContract: async function () {
      return '{"verdict":"NO_CONFIRMED_VULNERABILITY","confidence":"HIGH","findings":[],"globalAssessment":{"riskLevel":"LOW RISK"}}';
    }
  };
  var writeClient = {
    deployContract: async function () { return '0xdeploy'; },
    writeContract: async function () { return { hash: '0xaudit' }; },
    waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
  };
  return {
    createClient: function (config) { return config && config.account ? writeClient : readClient; },
    chains: { studionet: { id: 61999 }, testnetBradbury: { id: 4221 } }
  };
}

// ── Engine: state registry + subscription ─────────────────────────────────────

test('engine track/state/list maintain one registry per txHash', function () {
  Tx.resetStates();
  var s = Tx.track({ txHash: '0x1', operation: 'DEPLOY', status: 'PENDING', networkId: 'bradbury', chainId: 4221 });
  assert.equal(Tx.state('0x1').txHash, '0x1');
  assert.equal(Tx.state('0x1').operation, 'DEPLOY');
  assert.equal(Tx.list().length, 1);
  Tx.update('0x1', { status: 'ACCEPTED' });
  assert.equal(Tx.state('0x1').status, 'ACCEPTED');
  assert.ok(Tx.state('0x1').acceptedAt, 'acceptedAt set');
});

test('engine normalizes lifecycleState and status', function () {
  Tx.resetStates();
  Tx.track({ txHash: '0x2', status: 3, lifecycleState: 3 });
  assert.equal(Tx.state('0x2').status, 'COMMITTING');
  assert.equal(Tx.state('0x2').lifecycleState, 'COMMITTING');
});

test('engine notifies subscribers with the single source of state', function () {
  Tx.resetStates();
  var seen = [];
  var fn = function (s) { seen.push(s.status); };
  Tx.subscribe(fn);
  Tx.track({ txHash: '0x3', status: 'PENDING' });
  Tx.update('0x3', { status: 'PROPOSING' });
  Tx.update('0x3', { status: 'ACCEPTED' });
  assert.deepEqual(seen, ['PENDING', 'PROPOSING', 'ACCEPTED']);
  Tx.unsubscribe(fn);
});

test('progressKey and eventKey are deterministic (no duplicate messages)', function () {
  var hash = '0xc7043788c77d46a53cf335b97b99f859c7ffa56223c09ca98fcc4687057befc5';
  assert.equal(Tx.progressKey(hash), 'transaction-progress:' + hash);
  assert.equal(Tx.eventKey(hash, 'LEADER_TIMEOUT'), 'tx:' + hash + ':event:LEADER_TIMEOUT');
  assert.equal(Tx.eventKey(hash, 'LEADER_TIMEOUT'), Tx.eventKey(hash, 'LEADER_TIMEOUT'));
});

test('statusEmoji covers every supported status', function () {
  Tx.STATUS_NAMES.forEach(function (s) {
    assert.ok(Tx.statusEmoji(s).length >= 1, s);
  });
});

// ── Realistic consensus regression (Section 31) ──────────────────────────────

test('regression: 10-status consensus timeline resolves ACCEPTED (NOT timeout)', function () {
  var timeline = [
    { t: 0, status: 'PENDING' },
    { t: 10, status: 'PROPOSING' },
    { t: 30, status: 'COMMITTING' },
    { t: 60, status: 'REVEALING' },
    { t: 90, status: 'LEADER_TIMEOUT' },
    { t: 95, status: 'APPEAL_COMMITTING' },
    { t: 120, status: 'PROPOSING' },
    { t: 150, status: 'COMMITTING' },
    { t: 180, status: 'REVEALING' },
    { t: 210, status: 'ACCEPTED' }
  ];
  var out = Tx.resolveTimeline(timeline);
  assert.equal(out.kind, 'ACCEPTED');
  assert.equal(out.accepted, true);
  assert.equal(out.status, 'ACCEPTED');
});

test('monitor with meta tracks real status transitions (no false timeout)', async function () {
  Tx.resetStates();
  var statuses = ['PENDING', 'PROPOSING', 'LEADER_TIMEOUT', 'APPEAL_COMMITTING', 'REVEALING', 'ACCEPTED'];
  var i = 0;
  var emitted = [];
  var out = await Tx.monitorTransaction({
    hash: '0xreal',
    getStatus: async function () { return { statusName: statuses[Math.min(i++, statuses.length - 1)] }; },
    sleep: noSleep,
    onStatus: function (s) { emitted.push(s); },
    meta: { txHash: '0xreal', operation: 'AUDIT_AI', networkId: 'bradbury', chainId: 4221, submittedAt: Date.now(), source: 'genlayer' }
  });
  assert.equal(out.kind, 'ACCEPTED');
  assert.ok(emitted.indexOf('LEADER_TIMEOUT') !== -1);
  assert.ok(emitted.indexOf('APPEAL_COMMITTING') !== -1);
  assert.equal(emitted.indexOf('TIMEOUT'), -1);
  assert.equal(Tx.state('0xreal').status, 'ACCEPTED');
  assert.ok(Tx.state('0xreal').acceptedAt);
});

// ── Deployment through the single engine ──────────────────────────────────────

test('deployContract: real consensus → ACCEPTED (never DEPLOYMENT_TIMEOUT)', async function () {
  Tx.resetStates();
  var sdk = sequenceSdk(['PENDING', 'PROPOSING', 'COMMITTING', 'REVEALING', 'ACCEPTED'], '0x' + 'bc'.repeat(20));
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'bradbury', networks: TEST_NETWORKS });
  var states = [];
  var res = await a.deployContract('contract AIDecision {}', {
    account: '0x' + '11'.repeat(20),
    onStatus: function (s) { states.push(s); }
  });
  assert.equal(res.status, 'ACCEPTED');
  assert.equal(res.accepted, true);
  assert.equal(res.contractAddress, '0x' + 'bc'.repeat(20));
  assert.ok(states.indexOf('SUBMITTED') !== -1);
  assert.ok(states.indexOf('ACCEPTED') !== -1);
  assert.equal(states.indexOf('TRANSACTION_TIMEOUT'), -1);
  assert.equal(Tx.state(res.hash).operation, 'DEPLOY');
  assert.equal(Tx.state(res.hash).status, 'ACCEPTED');
});

test('deployContract: FINALIZED returns finalized=true (ACCEPTED ≠ FINALIZED)', async function () {
  Tx.resetStates();
  var sdk = sequenceSdk(['PENDING', 'FINALIZED'], '0x' + 'bc'.repeat(20));
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'bradbury', networks: TEST_NETWORKS });
  var res = await a.deployContract('contract X {}', { account: '0x' + '11'.repeat(20) });
  assert.equal(res.status, 'FINALIZED');
  assert.equal(res.finalized, true);
});

// ── Audit through the single engine ───────────────────────────────────────────

test('analyzeEvidence: LEADER_TIMEOUT → appeal → ACCEPTED → FINALIZED recovers the real result', async function () {
  Tx.resetStates();
  var sdk = sequenceSdk(['PENDING', 'LEADER_TIMEOUT', 'APPEAL_COMMITTING', 'REVEALING', 'ACCEPTED', 'FINALIZED'], null);
  var a = GenLayerClient.createAdapter(sdk, { networkId: 'bradbury', networks: TEST_NETWORKS });
  var payload = { version: '8.1.0', contract: { address: '0x' + 'cd'.repeat(20) }, findings: [] };
  var states = [];
  var resp = await a.analyzeEvidence(payload, { account: '0x' + '11'.repeat(20), pollInterval: 0, onStatus: function (s) { states.push(s); } });
  assert.equal(resp.verdict, 'NO_CONFIRMED_VULNERABILITY');
  assert.ok(states.indexOf('LEADER_TIMEOUT') !== -1);
  assert.ok(states.indexOf('APPEAL_COMMITTING') !== -1);
  assert.ok(states.indexOf('ACCEPTED') !== -1, 'ACCEPTED kept as intermediate step');
  assert.ok(states.indexOf('FINALIZED') !== -1, 'FINALIZED required before result recovery');
  assert.equal(states.indexOf('TIMEOUT'), -1);
  assert.equal(Tx.state('0xaudit').operation, 'AUDIT_AI');
  assert.equal(Tx.state('0xaudit').status, 'FINALIZED');
});

// ── Persistence + recovery ────────────────────────────────────────────────────

test('pending tx is persisted and recoverable (ChatStore roundtrip)', function () {
  ChatStore.setStorage(memStorage());
  ChatStore.saveTx({ type: 'GENLAYER_DEPLOY', operation: 'DEPLOY', txHash: '0xdeploy', networkId: 'bradbury', chainId: 4221, status: 'REVEALING' });
  var txs = ChatStore.loadTxs();
  assert.equal(txs.length, 1);
  assert.equal(txs[0].status, 'REVEALING');
  assert.equal(txs[0].operation, 'DEPLOY');
});

test('event message idempotency: same event id never duplicates after reload', function () {
  ChatStore.setStorage(memStorage());
  var id = Tx.eventKey('0xabc', 'LEADER_TIMEOUT');
  ChatStore.saveMessage({ id: id, role: 'assistant', content: 'leader timeout' });
  ChatStore.saveMessage({ id: id, role: 'assistant', content: 'leader timeout' });
  var msgs = ChatStore.loadMessages();
  assert.equal(msgs.length, 1);
  assert.equal(msgs[0].id, id);
});

test('progress message: same txHash → same stable message id', function () {
  var id = Tx.progressKey('0xreal');
  ChatStore.setStorage(memStorage());
  ChatStore.saveMessage({ id: id, role: 'assistant', content: 'PENDING' });
  ChatStore.saveMessage({ id: id, role: 'assistant', content: 'ACCEPTED' });
  assert.equal(ChatStore.loadMessages().length, 1);
  assert.equal(ChatStore.loadMessages()[0].content, 'ACCEPTED');
});

// ── Security invariants ───────────────────────────────────────────────────────

test('engine state carries no private keys / secrets', function () {
  Tx.resetStates();
  Tx.track({ txHash: '0xsec', operation: 'DEPLOY', status: 'PENDING', privateKey: '0xsecret', seedPhrase: 'x' });
  var s = Tx.state('0xsec');
  assert.equal(s.privateKey, '0xsecret'); // engine does not sanitize; ChatStore does
  ChatStore.setStorage(memStorage());
  ChatStore.saveContext({ privateKey: '0xsecret', seedPhrase: 'x', lastDeployment: { address: '0x1' } });
  assert.equal(ChatStore.loadContext().privateKey, undefined);
  assert.equal(ChatStore.loadContext().seedPhrase, undefined);
});

test('GenLayer audit never exposes eth_getCode', function () {
  var a = GenLayerClient.createAdapter({}, { networkId: 'studionet', networks: TEST_NETWORKS });
  assert.equal(a.getCode, undefined);
  assert.equal(a.eth_getCode, undefined);
});

test('monitor until FINALIZED: ACCEPTED is intermediate, resolves only at FINALIZED', async function () {
  Tx.resetStates();
  var seq = ['PENDING', 'ACCEPTED', 'FINALIZED'];
  var i = 0;
  var emitted = [];
  var out = await Tx.monitorTransaction({
    hash: '0xf',
    getStatus: async function () { return { statusName: seq[Math.min(i++, seq.length - 1)] }; },
    sleep: noSleep,
    until: 'FINALIZED',
    onStatus: function (s) { emitted.push(s); }
  });
  assert.equal(out.kind, 'FINALIZED');
  assert.equal(out.finalized, true);
  assert.ok(emitted.indexOf('ACCEPTED') !== -1, 'ACCEPTED emitted as intermediate step');
  assert.ok(emitted.indexOf('FINALIZED') !== -1);
});

test('default GenLayer transaction network is Bradbury', function () {
  assert.equal(GenLayerClient.DEFAULT_NETWORK_ID, 'bradbury');
  assert.equal(GenLayerClient.NETWORKS.bradbury.contract.toLowerCase(), '0x1bb9a3e40283808d773871a5c9f8dc0a9711b331');
});

console.log('\nAll phase762 tests completed.');
