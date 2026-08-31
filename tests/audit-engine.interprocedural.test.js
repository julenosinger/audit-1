'use strict';
// Phase 5 tests: interprocedural analysis (function graph, storage graph, evidence graph).
// Run with:  node tests/audit-engine.interprocedural.test.js
const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../public/audit-engine.js');

function fakeBlock(id, startPc, terminator, jumpTargetPc, dynamicJump) {
  return {
    id: id, startPc: startPc, endPc: startPc + 1, instructions: [], successors: [], predecessors: [],
    terminator: terminator, reachable: true, dead: false, reach: 'REACHABLE',
    jumpTargetPc: (jumpTargetPc !== undefined ? jumpTargetPc : null), dynamicJump: !!dynamicJump
  };
}

// ── Bytecode hash / payload ──────────────────────────────────────────────────
test('bytecodeHash is deterministic and content-sensitive', function () {
  assert.equal(Engine.bytecodeHash('6000'), Engine.bytecodeHash('6000'));
  assert.notEqual(Engine.bytecodeHash('6000'), Engine.bytecodeHash('6001'));
});

test('analyze produces versioned payload with evidence graph', function () {
  var r = Engine.analyze('600054f16000600155', { address: '0x' + 'ab'.repeat(20) });
  assert.equal(r.analysisVersion, '5.0.0');
  assert.ok(r.bytecodeHash);
  assert.ok(r.payload);
  assert.equal(r.payload.contract.bytecodeHash, r.bytecodeHash);
  assert.ok(r.payload.analysis.functionGraph);
  assert.ok(r.payload.analysis.storageGraph);
  assert.ok(r.payload.analysis.evidenceGraph);
});

// ── Function graph ───────────────────────────────────────────────────────────
test('function graph: nodes, internal edges, cycle, dynamic edge', function () {
  var cfg = { blocks: [fakeBlock(0, 0, 'JUMP', 10), fakeBlock(1, 10, 'JUMP', 0), fakeBlock(2, 20, 'JUMP', null, true)], entryBlock: 0 };
  var functionMap = {
    'aaaa': { selector: '0xaaaa', name: 'f1', entryPc: 0, confidence: 'HIGH' },
    'bbbb': { selector: '0xbbbb', name: 'f2', entryPc: 10, confidence: 'HIGH' }
  };
  var g = Engine.buildFunctionGraph(cfg, functionMap);
  assert.equal(g.nodes.length, 2);
  var types = g.edges.map(function (e) { return e.type; });
  assert.equal(types.filter(function (t) { return t === 'INTERNAL'; }).length, 2);
  assert.equal(types.filter(function (t) { return t === 'DYNAMIC'; }).length, 1);
  // cycle: fn_0 -> fn_1 and fn_1 -> fn_0
  assert.ok(g.edges.some(function (e) { return e.from === 'fn_0' && e.to === 'fn_1'; }));
  assert.ok(g.edges.some(function (e) { return e.from === 'fn_1' && e.to === 'fn_0'; }));
});

test('function graph: no functions => empty', function () {
  var cfg = { blocks: [fakeBlock(0, 0, 'STOP')], entryBlock: 0 };
  var g = Engine.buildFunctionGraph(cfg, {});
  assert.equal(g.nodes.length, 0);
  assert.equal(g.edges.length, 0);
});

// ── Storage graph ────────────────────────────────────────────────────────────
test('storage graph: slots, WRITE_TO_READ dependency, unknown slot excluded', function () {
  var df = {
    storageReads: [
      { type: 'storage-read', slotKey: '0x0', slot: '0x0', pc: 20, blockId: 0 },
      { type: 'storage-read', slotKey: null, slot: 'UNKNOWN', pc: 30, blockId: 0 }
    ],
    storageWrites: [
      { type: 'storage-write', slotKey: '0x0', slot: '0x0', pc: 10, blockId: 0, value: '0x1' },
      { type: 'storage-write', slotKey: '0x1', slot: '0x1', pc: 40, blockId: 0, value: '0x2' }
    ]
  };
  var g = Engine.buildStorageGraph(df);
  assert.ok(g.slots.indexOf('0x0') !== -1);
  assert.ok(g.slots.indexOf('0x1') !== -1);
  // write @10 -> read @20 same slot => WRITE_TO_READ
  assert.ok(g.dependencies.some(function (d) { return d.type === 'WRITE_TO_READ' && d.slot === '0x0'; }));
  // unknown slot (null slotKey) never treated as a real slot
  assert.ok(g.slots.indexOf('UNKNOWN') === -1);
});

test('storage graph: WRITE_TO_WRITE dependency', function () {
  var df = {
    storageReads: [],
    storageWrites: [
      { type: 'storage-write', slotKey: '0x5', slot: '0x5', pc: 10, blockId: 0 },
      { type: 'storage-write', slotKey: '0x5', slot: '0x5', pc: 50, blockId: 0 }
    ]
  };
  var g = Engine.buildStorageGraph(df);
  assert.ok(g.dependencies.some(function (d) { return d.type === 'WRITE_TO_WRITE' && d.slot === '0x5'; }));
});

// ── Evidence graph ───────────────────────────────────────────────────────────
test('evidence graph: valid nodes and edges, all edge refs resolve', function () {
  var r = Engine.analyze('600054f16000600155');
  var g = r.evidenceGraph;
  assert.ok(g.nodes.length > 0);
  var ids = {};
  g.nodes.forEach(function (n) { ids[n.id] = true; });
  g.edges.forEach(function (e) {
    assert.ok(ids[e.from], 'edge from exists: ' + e.from);
    assert.ok(ids[e.to], 'edge to exists: ' + e.to);
  });
  // a finding node exists (reentrancy-pattern)
  assert.ok(g.nodes.some(function (n) { return n.type === 'FINDING' && n.id === 'reentrancy-pattern'; }));
});

test('evidence trace returns finding + data-flow evidence', function () {
  var r = Engine.analyze('600054f16000600155');
  var t = Engine.buildEvidenceTrace(r, 'reentrancy-pattern');
  assert.equal(t.findingId, 'reentrancy-pattern');
  assert.ok(t.trace.some(function (s) { return s.type === 'FINDING'; }));
  assert.ok(t.trace.some(function (s) { return s.type === 'DATA_FLOW'; }));
});

test('evidence trace for unknown finding returns empty trace', function () {
  var r = Engine.analyze('600054f16000600155');
  var t = Engine.buildEvidenceTrace(r, 'does-not-exist');
  assert.equal(t.trace.length, 0);
});

console.log('\nAll interprocedural tests completed.');
