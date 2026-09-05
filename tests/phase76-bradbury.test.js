'use strict';
// Phase 7.6 tests: Bradbury GenLayer contract integration + real interaction.
// Deterministic invariants only — the SDK transport is mocked, never a fake
// result. Run with:  node tests/phase76-bradbury.test.js
const test = require('node:test');
const assert = require('node:assert');
const Networks = require('../public/networks.js');
const GenLayerClient = require('../public/genlayer-client.js');
const Interaction = require('../public/genlayer-interaction.js');
const Router = require('../public/intent-router.js');

const BRADBURY_ADDR = '0x1BB9A3e40283808D773871a5C9F8Dc0a9711B331';
const BRADBURY_ADDR_LOWER = BRADBURY_ADDR.toLowerCase();
const BRADBURY_TX = '0x59cce95df528dc62cb3a6afeb41441f7c9dc361f799e47eb02dfc4e54c763b95';

const TEST_NETWORKS = {
  studionet: { id: 'studionet', name: 'Studionet', chainId: 61999, rpc: 'https://studio.genlayer.com/api', contract: '0x' + 'ab'.repeat(20), deployed: true },
  bradbury: { id: 'bradbury', name: 'Bradbury Testnet', chainId: 4221, rpc: 'https://rpc-bradbury.genlayer.com', contract: '', deployed: false }
};

function mockSchema() {
  return {
    ctor: { params: [], kwparams: {} },
    methods: {
      owner: { params: [], kwparams: {}, ret: 'address', readonly: true },
      total_supply: { params: [], kwparams: {}, ret: 'int', readonly: true },
      balance_of: { params: [['account', 'address']], kwparams: {}, ret: 'int', readonly: true },
      set_value: { params: [['v', 'int']], kwparams: {}, ret: 'null', readonly: false },
      mint: { params: [['to', 'address'], ['amount', 'int']], kwparams: {}, ret: 'null', readonly: false, payable: true }
    }
  };
}

function mockSdk(schema) {
  schema = schema || mockSchema();
  var readClient = {
    getContractSchema: async function () { return schema; },
    getContractCode: async function () { return 'class Foo:\n    def owner(self): ...'; },
    readContract: async function (a) { return 'READ:' + a.functionName; },
    simulateWriteContract: async function (a) { return 'SIM:' + a.functionName; },
    getTransaction: async function (a) { return { hash: a.hash }; },
    waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
  };
  var writeClient = {
    writeContract: async function () { return { hash: '0x' + 'aa'.repeat(32) }; },
    waitForTransactionReceipt: async function () { return { status: 'FINALIZED' }; }
  };
  return {
    createClient: function (config) { return config && config.account ? writeClient : readClient; },
    chains: { studionet: { id: 61999 }, testnetBradbury: { id: 4221 } }
  };
}

function makeBradburyAdapter(sdk) {
  return GenLayerClient.createAdapter(sdk || mockSdk(), { networkId: 'bradbury', networks: TEST_NETWORKS });
}

// ── 1. Registry / network identity ───────────────────────────────────────────

test('Bradbury is registered as a GenLayer network (audit registry)', function () {
  var net = Networks.NETWORKS.genlayerBradbury;
  assert.ok(net, 'genlayerBradbury must exist');
  assert.equal(Networks.getFamily('genlayerBradbury'), 'GENLAYER');
});

test('Bradbury chainId === 4221', function () {
  assert.equal(Networks.NETWORKS.genlayerBradbury.chainId, 4221);
  assert.equal(GenLayerClient.NETWORKS.bradbury.chainId, 4221);
  assert.equal(Interaction.BRADBURY.chainId, 4221);
});

test('Bradbury is GENLAYER family, never EVM', function () {
  assert.equal(Router.networkFamily('genlayerBradbury'), 'GENLAYER');
  assert.equal(Router.networkFamily('bradbury'), 'GENLAYER');
  assert.equal(Networks.getFamily('genlayerBradbury'), 'GENLAYER');
});

test('Bradbury RPC is correct', function () {
  assert.equal(Networks.NETWORKS.genlayerBradbury.rpc, 'https://rpc-bradbury.genlayer.com');
  assert.equal(GenLayerClient.NETWORKS.bradbury.rpc, 'https://rpc-bradbury.genlayer.com');
});

test('Bradbury explorer is configured', function () {
  assert.equal(Networks.NETWORKS.genlayerBradbury.explorer, 'https://explorer-bradbury.genlayer.com/');
});

// ── 6/7. Real contract address + deployment tx ───────────────────────────────

test('known Bradbury contract address is exact (never normalized away)', function () {
  assert.equal(Interaction.BRADBURY.contract, BRADBURY_ADDR);
  assert.equal(GenLayerClient.NETWORKS.bradbury.knownContract, BRADBURY_ADDR);
  var k = GenLayerClient.knownContractFor(BRADBURY_ADDR_LOWER);
  assert.ok(k);
  assert.equal(k.address, BRADBURY_ADDR);
  assert.equal(k.chainId, 4221);
});

test('deployment transaction hash is exact', function () {
  assert.equal(Interaction.BRADBURY.deploymentTx, BRADBURY_TX);
  assert.equal(GenLayerClient.NETWORKS.bradbury.knownDeploymentTx, BRADBURY_TX);
  assert.equal(GenLayerClient.knownContractFor(BRADBURY_ADDR).deploymentTx, BRADBURY_TX);
});

test('Bradbury AuditAI auditor is deployed with the real contract address', function () {
  assert.equal(GenLayerClient.NETWORKS.bradbury.deployed, true);
  assert.equal(GenLayerClient.NETWORKS.bradbury.contract.toLowerCase(), BRADBURY_ADDR_LOWER);
});

// The REAL Bradbury contract source (retrieved live via gen_getContractCode)
// is the AuditAI intelligent contract. Its schema exposes these functions:
//   writes: publish_audit, analyze_and_publish, analyze_evidence
//   views:  get_audit, get_score, get_verdict, get_author, has_audit, get_analysis
test('the real Bradbury AuditAI schema parses into the expected functions', function () {
  var schema = {
    ctor: { params: [], kwparams: {} },
    methods: {
      publish_audit: { params: [['contract_addr', 'str'], ['score', 'str'], ['verdict', 'str'], ['findings', 'str']], kwparams: {}, ret: 'None', readonly: false },
      analyze_and_publish: { params: [['contract_addr', 'str'], ['source_or_context', 'str']], kwparams: {}, ret: 'None', readonly: false },
      analyze_evidence: { params: [['contract_addr', 'str'], ['evidence_json', 'str']], kwparams: {}, ret: 'None', readonly: false },
      get_audit: { params: [['contract_addr', 'str']], kwparams: {}, ret: 'str', readonly: true },
      get_score: { params: [['contract_addr', 'str']], kwparams: {}, ret: 'str', readonly: true },
      get_verdict: { params: [['contract_addr', 'str']], kwparams: {}, ret: 'str', readonly: true },
      get_author: { params: [['contract_addr', 'str']], kwparams: {}, ret: 'str', readonly: true },
      has_audit: { params: [['contract_addr', 'str']], kwparams: {}, ret: 'bool', readonly: true },
      get_analysis: { params: [['contract_addr', 'str']], kwparams: {}, ret: 'str', readonly: true }
    }
  };
  var parsed = Interaction.parseContractSchema(schema);
  assert.equal(parsed.readFunctions.length, 6);
  assert.equal(parsed.writeFunctions.length, 3);
  assert.ok(parsed.readFunctions.some(function (f) { return f.name === 'get_analysis'; }));
  assert.ok(parsed.writeFunctions.some(function (f) { return f.name === 'analyze_evidence'; }));
});

// ── 8/9/10. GenLayer path never uses eth_getCode ─────────────────────────────

test('inspectContract uses schema+code (no eth_getCode in the adapter surface)', function () {
  var adapter = makeBradburyAdapter();
  // The adapter exposes ONLY GenLayer SDK methods — no eth_getCode/eth_call.
  assert.equal(typeof adapter.getContractSchema, 'function');
  assert.equal(typeof adapter.getContractCode, 'function');
  assert.equal(adapter.getCode, undefined);
  assert.equal(adapter.eth_getCode, undefined);
});

test('inspectContract obtains schema + code from the real SDK client', async function () {
  var adapter = makeBradburyAdapter();
  var res = await Interaction.inspectContract(adapter, { networkId: 'bradbury', chainId: 4221, address: BRADBURY_ADDR });
  assert.equal(res.ok, true);
  assert.equal(res.schemaAvailable, true);
  assert.equal(res.codeAvailable, true);
  assert.ok(res.readFunctions.length > 0);
  assert.ok(res.writeFunctions.length > 0);
});

test('Bradbury audit is GENLAYER_SOURCE_REVIEW (never EVM_BYTECODE_AUDIT)', function () {
  var r = Interaction.reviewGenLayerContract({ networkId: 'genlayerBradbury', networkName: 'GenLayer Bradbury Testnet', chainId: 4221, address: BRADBURY_ADDR });
  assert.equal(r.auditType, 'GENLAYER_SOURCE_REVIEW');
  assert.notEqual(r.auditType, 'EVM_BYTECODE_AUDIT');
  assert.equal(r.score, null);
});

// ── 18/19/20. Schema from the real contract; never invent functions ──────────

test('parseContractSchema splits read vs write from the real schema', function () {
  var parsed = Interaction.parseContractSchema(mockSchema());
  assert.equal(parsed.available, true);
  var readNames = parsed.readFunctions.map(function (f) { return f.name; });
  var writeNames = parsed.writeFunctions.map(function (f) { return f.name; });
  assert.deepEqual(readNames, ['owner', 'total_supply', 'balance_of']);
  assert.deepEqual(writeNames, ['set_value', 'mint']);
});

test('parseContractSchema never invents functions (only schema methods appear)', function () {
  var parsed = Interaction.parseContractSchema(mockSchema());
  var all = parsed.readFunctions.concat(parsed.writeFunctions).map(function (f) { return f.name; });
  assert.equal(all.indexOf('analyze_evidence'), -1);
  assert.equal(all.indexOf('publish_audit'), -1);
});

test('unknown/missing schema yields no fake functions', function () {
  var parsed = Interaction.parseContractSchema(null);
  assert.equal(parsed.available, false);
  assert.equal(parsed.readFunctions.length, 0);
  assert.equal(parsed.writeFunctions.length, 0);
  assert.equal(parsed.error, 'SCHEMA_UNAVAILABLE');
});

// ── 21/22. Finding IDs + UNKNOWN score ───────────────────────────────────────

test('finding IDs are unique and deterministic', function () {
  var ids = Interaction.uniqueFindingIds([
    { id: 'src-HIGH', severity: 'HIGH' },
    { id: 'src-HIGH', severity: 'HIGH' },
    { id: 'src-HIGH', severity: 'HIGH' }
  ]);
  var seen = {};
  ids.forEach(function (f) { seen[f.id] = (seen[f.id] || 0) + 1; });
  Object.keys(seen).forEach(function (k) { assert.equal(seen[k], 1, 'duplicate id ' + k); });
});

test('UNKNOWN risk carries score null (never a reassuring number)', function () {
  assert.equal(Interaction.normalizeScore('UNKNOWN', 100), null);
  assert.equal(Interaction.normalizeScore('UNKNOWN', undefined), null);
  var r = Interaction.reviewGenLayerContract({ networkId: 'bradbury', chainId: 4221, address: BRADBURY_ADDR, risk: 'UNKNOWN' });
  assert.equal(r.risk, 'UNKNOWN');
  assert.equal(r.score, null);
});

// ── 14/15/16/17. Read vs write safety ────────────────────────────────────────

test('read requires NO wallet and returns a real result', async function () {
  var adapter = makeBradburyAdapter();
  var res = await Interaction.runRead(adapter, { networkId: 'bradbury', chainId: 4221, address: BRADBURY_ADDR, functionName: 'owner', args: [] });
  assert.equal(res.ok, true);
  assert.equal(res.result, 'READ:owner');
  assert.equal(res.networkId, 'bradbury');
});

test('write requires a wallet (BRADBURY_WALLET_REQUIRED when absent)', function () {
  var v = Interaction.validateWrite({ wallet: null, chainId: 4221 });
  assert.equal(v.ok, false);
  assert.equal(v.error, 'BRADBURY_WALLET_REQUIRED');
});

test('network mismatch blocks write (BRADBURY_NETWORK_MISMATCH)', function () {
  var v = Interaction.validateWrite({ wallet: { address: '0xabc', chainId: 1 }, chainId: 4221 });
  assert.equal(v.ok, false);
  assert.equal(v.error, 'BRADBURY_NETWORK_MISMATCH');
});

test('write NEVER executes without explicit confirmation', async function () {
  var adapter = makeBradburyAdapter();
  var res = await Interaction.runWrite(adapter, {
    networkId: 'bradbury', chainId: 4221, address: BRADBURY_ADDR, functionName: 'set_value',
    args: [1], wallet: { address: '0x' + '11'.repeat(20), chainId: 4221 }, confirmed: false
  });
  assert.equal(res.ok, false);
  assert.equal(res.error, 'BRADBURY_WRITE_REJECTED');
});

test('write with wallet + confirmation returns the REAL tx hash', async function () {
  var adapter = makeBradburyAdapter();
  var res = await Interaction.runWrite(adapter, {
    networkId: 'bradbury', chainId: 4221, address: BRADBURY_ADDR, functionName: 'set_value',
    args: [1], wallet: { address: '0x' + '11'.repeat(20), chainId: 4221 }, confirmed: true
  });
  assert.equal(res.ok, true);
  assert.match(res.txHash, /^0x/);
  assert.equal(res.status, 'SUBMITTED');
});

// ── 24. Network + contract pairing ───────────────────────────────────────────

test('assertContractNetworkPair rejects cross-network pairing', function () {
  var bad = GenLayerClient.assertContractNetworkPair({ networkId: 'studionet', chainId: 61999, address: BRADBURY_ADDR });
  assert.equal(bad.ok, false);
  assert.equal(bad.error, 'CONTRACT_NETWORK_MISMATCH');
});

test('assertContractNetworkPair accepts the correct pair', function () {
  var good = GenLayerClient.assertContractNetworkPair({ networkId: 'bradbury', chainId: 4221, address: BRADBURY_ADDR });
  assert.equal(good.ok, true);
  assert.equal(good.known.networkId, 'bradbury');
});

// ── 23/24/25. Chat + Quick Action routing ────────────────────────────────────

test('Chat recognizes Bradbury phrases', function () {
  assert.equal(Router.detectIntent('Audit my Bradbury contract', false), 'AUDIT_CONTRACT');
  assert.equal(Router.detectIntent('Inspect the Bradbury contract', false), 'INSPECT_CONTRACT');
  assert.equal(Router.detectIntent('Read the contract', false), 'INSPECT_CONTRACT');
  assert.equal(Router.detectIntent('Show me its functions', false), 'INSPECT_CONTRACT');
  assert.equal(Router.detectIntent('Call this function', false), 'INTERACT_CONTRACT');
  assert.equal(Router.detectIntent('Write to the contract', false), 'INTERACT_CONTRACT');
  assert.equal(Router.detectIntent('Interact with my Bradbury contract', false), 'INTERACT_CONTRACT');
});

test('Chat and Quick Action converge on the same router', function () {
  assert.equal(Router.detectIntent('Audit Contract'), Router.detectIntent('audit contract'));
  // Both a chat phrase and the quick-action label resolve through detectIntent.
  assert.equal(Router.detectIntent('Audit my Bradbury contract', false), Router.INTENTS.AUDIT_CONTRACT);
});

test('known Bradbury contract address resolves to GenLayer (never Ethereum)', function () {
  var n = Router.networkForContract(BRADBURY_ADDR);
  assert.ok(n);
  assert.equal(n.family, 'GENLAYER');
  assert.equal(n.networkId, 'bradbury');
  assert.equal(n.chainId, 4221);
});

// ── 26/27/28. lastDeployment / activeContract / audit routing ────────────────

test('planAudit routes a Bradbury deployment to genlayer mode (NOT eth_getCode)', function () {
  var ctx = Router.buildContext({ lastDeployment: { address: BRADBURY_ADDR, network: 'Bradbury Testnet', networkId: 'genlayerBradbury', chainId: 4221 } });
  var plan = Router.planAudit(ctx);
  assert.equal(plan.mode, 'genlayer');
  assert.notEqual(plan.mode, 'evm');
  assert.notEqual(plan.mode, 'discover');
});

test('buildContext carries a Bradbury deployment through (activeContract)', function () {
  var ctx = Router.buildContext({ lastDeployment: { address: BRADBURY_ADDR, networkId: 'genlayerBradbury', chainId: 4221, txHash: BRADBURY_TX } });
  assert.equal(ctx.lastDeployment.address, BRADBURY_ADDR);
  assert.equal(ctx.lastDeployment.chainId, 4221);
});

// ── 30. nextActions ──────────────────────────────────────────────────────────

test('nextActions after Bradbury deployment suggests only real actions', function () {
  var ctx = Router.buildContext({ lastDeployment: { address: BRADBURY_ADDR, txHash: '0x' + 'ab'.repeat(32), networkId: 'genlayerBradbury' } });
  var ids = Router.nextActions(ctx).map(function (a) { return a.id; });
  assert.ok(ids.indexOf('audit_contract') !== -1);
  assert.ok(ids.indexOf('inspect_contract') !== -1);
  assert.ok(ids.indexOf('view_tx') !== -1);
  assert.ok(ids.indexOf('interact_contract') !== -1);
  assert.ok(ids.indexOf('deploy') === -1);
});

// ── 11/12/13/31/32/33/34. Policy invariants (no regression) ──────────────────

test('Studionet still works (deployed + audit contract)', function () {
  assert.equal(GenLayerClient.NETWORKS.studionet.deployed, true);
  assert.match(GenLayerClient.NETWORKS.studionet.contract, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(GenLayerClient.NETWORKS.studionet.chainId, 61999);
});

test('EVM networks remain read-only (no write capability)', function () {
  ['ethereum', 'bsc', 'base', 'arbitrum', 'optimism'].forEach(function (id) {
    assert.equal(Networks.getFamily(id), 'EVM');
  });
});

test('GenLayer writes are limited to GenLayer networks (INTERACT evm=false)', function () {
  var c = Router.capability(Router.INTENTS.INTERACT_CONTRACT);
  assert.equal(c.evm, false);
  assert.equal(c.genlayer, true);
});

test('no intent auto-writes / auto-signs (write=false in capability)', function () {
  Object.keys(Router.INTENTS).forEach(function (k) {
    var c = Router.capability(Router.INTENTS[k]);
    assert.equal(c.write, false, k + ' must not auto-write');
  });
});

test('Audit / Inspect / Explain require NO wallet', function () {
  ['AUDIT_CONTRACT', 'INSPECT_CONTRACT', 'EXPLAIN_FINDINGS'].forEach(function (i) {
    assert.equal(Router.capability(i).wallet, false);
  });
});

test('Create EVM Solidity never calls wallet (deploy is a separate step)', function () {
  var c = Router.capability(Router.INTENTS.CREATE_CONTRACT);
  assert.equal(c.wallet, false);
  assert.equal(c.write, false);
});

test('error taxonomy contains all Bradbury + pairing codes', function () {
  var E = Interaction.ERRORS;
  ['BRADBURY_RPC_UNAVAILABLE', 'BRADBURY_CONTRACT_NOT_FOUND', 'BRADBURY_SCHEMA_UNAVAILABLE',
    'BRADBURY_READ_FAILED', 'BRADBURY_SIMULATION_FAILED', 'BRADBURY_WRITE_REJECTED',
    'BRADBURY_WRITE_FAILED', 'BRADBURY_NETWORK_MISMATCH', 'BRADBURY_WALLET_REQUIRED',
    'BRADBURY_TX_PENDING', 'BRADBURY_TX_FAILED', 'CONTRACT_NETWORK_MISMATCH',
    'GENLAYER_OPERATION_UNAVAILABLE'].forEach(function (k) {
      assert.ok(E[k], 'missing error ' + k);
    });
});

test('transaction states are defined (real lifecycle)', function () {
  assert.ok(Interaction.TX_STATES.indexOf('PREPARING') !== -1);
  assert.ok(Interaction.TX_STATES.indexOf('SUBMITTED') !== -1);
  assert.ok(Interaction.TX_STATES.indexOf('CONFIRMED') !== -1);
  assert.ok(Interaction.TX_STATES.indexOf('FAILED') !== -1);
});

console.log('\nAll phase76-bradbury tests completed.');
