// ═══════════════════════════════════════════════════════════════════════════════
// AuditAI — Local Audit Engine (deterministic, zero LLM)
//
// A technically honest static analyzer for EVM bytecode:
//
//   bytecode → EVM Disassembler → Control Flow Graph → Reachability
//            → Stack/Selector analysis → Data-Flow Analysis → Security Rules
//            → Finding Engine → Risk Engine
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
// LIMITATIONS (important): disassembly is still *linear* (bytes are decoded
// sequentially); the control-flow layer only follows statically-resolvable jumps.
// Jump tables / dynamic jumps are flagged (analysis completeness = PARTIAL), and
// blocks that can only be reached via a dynamic jump are treated as "maybe
// reachable" (never asserted as dead). Bytes after a terminal opcode that are
// not JUMPDESTs are treated as unreachable/dead. No data-flow or inter-
// procedural analysis is performed. ABI-based findings are only produced when an
// ABI is supplied.
//
// Public API (window.AuditEngine):
//   disassemble(bytecode)            -> { valid, error, instructions[] }
//   buildCfg(instructions)           -> { blocks, edges, entryBlock, stats }
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

  var VERSION = '4.0.0';

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
        instructions.push({ pc: pc, opcode: 'INVALID', byte: b, argument: '', size: 1 });
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
      instructions.push({ pc: pc, opcode: op.name, byte: b, argument: arg, size: 1 + imm, truncated: imm > 0 && arg.length !== imm * 2 });
      pc += 1 + imm;
    }
    return { valid: true, error: null, instructions: instructions };
  }

  // ── 2b. Control Flow Analysis ──────────────────────────────────────────────
  function isTerminator(opcode) {
    return opcode === 'STOP' || opcode === 'RETURN' || opcode === 'REVERT' ||
      opcode === 'INVALID' || opcode === 'SELFDESTRUCT' ||
      opcode === 'JUMP' || opcode === 'JUMPI';
  }

  function toBig(x) {
    if (typeof x === 'bigint') return x;
    if (typeof x === 'number') return BigInt(x);
    if (typeof x === 'string') return BigInt(x); // '0x…' or decimal
    return BigInt(0);
  }

  // Limited symbolic stack executor: models PUSH/DUP/SWAP/POP and a small set of
  // arithmetic/bitwise/comparison ops. Any other opcode invalidates the stack
  // (treated as UNKNOWN). Never guesses — if unsure, the result is UNKNOWN.
  function execBlockStack(list) {
    var stack = []; // {k:'const', v:BigInt} | {k:'unknown'}
    function U() { return { k: 'unknown' }; }
    function C(v) { return { k: 'const', v: toBig(v) }; }
    for (var i = 0; i < list.length; i++) {
      var op = list[i].opcode, m;
      if (op === 'PUSH0') { stack.push(C(0)); continue; }
      if ((m = /^PUSH(\d+)$/.exec(op))) {
        var n = parseInt(m[1], 10);
        stack.push(list[i].argument.length === 2 * n ? C('0x' + list[i].argument) : U());
        continue;
      }
      if ((m = /^DUP(\d+)$/.exec(op))) {
        var dn = parseInt(m[1], 10);
        stack.push(stack.length >= dn ? stack[stack.length - dn] : U());
        continue;
      }
      if ((m = /^SWAP(\d+)$/.exec(op))) {
        var sn = parseInt(m[1], 10);
        if (stack.length >= sn + 1) {
          var top = stack.pop(); var idx = stack.length - sn; var other = stack[idx];
          stack[idx] = top; stack.push(other);
        } else {
          for (var k2 = 0; k2 < stack.length; k2++) stack[k2] = U();
        }
        continue;
      }
      if (op === 'POP') { stack.pop(); continue; }
      if (op === 'ADD' || op === 'MUL' || op === 'AND' || op === 'OR' || op === 'XOR') {
        var a = stack.pop(), b = stack.pop();
        if (a && b && a.k === 'const' && b.k === 'const') {
          var r;
          if (op === 'ADD') r = a.v + b.v; else if (op === 'MUL') r = a.v * b.v;
          else if (op === 'AND') r = a.v & b.v; else if (op === 'OR') r = a.v | b.v;
          else r = a.v ^ b.v;
          stack.push(C(r));
        } else stack.push(U());
        continue;
      }
      if (op === 'SUB') {
        var s1 = stack.pop(), s2 = stack.pop();
        stack.push((s1 && s2 && s1.k === 'const' && s2.k === 'const') ? C(s2.v - s1.v) : U());
        continue;
      }
      if (op === 'EQ' || op === 'LT' || op === 'GT') {
        var e1 = stack.pop(), e2 = stack.pop();
        if (e1 && e2 && e1.k === 'const' && e2.k === 'const') {
          var ev;
          if (op === 'EQ') ev = (e1.v === e2.v) ? BigInt(1) : BigInt(0);
          else if (op === 'LT') ev = (e2.v < e1.v) ? BigInt(1) : BigInt(0);
          else ev = (e2.v > e1.v) ? BigInt(1) : BigInt(0);
          stack.push(C(ev));
        } else stack.push(U());
        continue;
      }
      if (op === 'ISZERO') {
        var z = stack.pop();
        stack.push((z && z.k === 'const') ? C(z.v === BigInt(0) ? BigInt(1) : BigInt(0)) : U());
        continue;
      }
      if (op === 'SHL' || op === 'SHR') {
        var sh = stack.pop(), val = stack.pop();
        stack.push((sh && val && sh.k === 'const' && val.k === 'const') ? C(op === 'SHL' ? (val.v << sh.v) : (val.v >> sh.v)) : U());
        continue;
      }
      // Unsupported opcode — we cannot model its stack effect; invalidate.
      for (var k3 = 0; k3 < stack.length; k3++) stack[k3] = U();
    }
    return stack;
  }

  function resolveJumpTarget(block) {
    var list = block.instructions.slice(0, block.instructions.length - 1); // exclude terminator
    var stack = execBlockStack(list);
    var top = stack[stack.length - 1];
    if (top && top.k === 'const') {
      var num = Number(top.v);
      return (Number.isFinite(num) && num >= 0 && num < 0x10000000) ? num : null;
    }
    return null;
  }

  function buildCfg(instructions) {
    var jumpdests = {};
    instructions.forEach(function (ins) { if (ins.opcode === 'JUMPDEST') jumpdests[ins.pc] = true; });

    var blocks = [], cur = null;
    instructions.forEach(function (ins) {
      var startNew = !cur || jumpdests[ins.pc];
      if (startNew) {
        cur = {
          id: blocks.length, startPc: ins.pc, endPc: null,
          instructions: [], successors: [], predecessors: [],
          terminator: null, reachable: false, dead: false,
          jumpTargetPc: null, dynamicJump: false
        };
        blocks.push(cur);
      }
      ins.block = cur.id;
      cur.instructions.push(ins);
      cur.endPc = ins.pc + ins.size;
      if (isTerminator(ins.opcode)) { cur.terminator = ins.opcode; cur = null; }
    });

    var edges = [];
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i];
      var last = b.instructions[b.instructions.length - 1];
      var next = blocks[i + 1] || null;

      if (last.opcode === 'JUMP' || last.opcode === 'JUMPI') {
        var target = resolveJumpTarget(b);
        if (target !== null && jumpdests[target]) {
          b.jumpTargetPc = target;
          var tblock = null;
          for (var t = 0; t < blocks.length; t++) { if (blocks[t].startPc === target) { tblock = blocks[t]; break; } }
          if (tblock) {
            b.successors.push(tblock.id);
            edges.push({ from: b.id, to: tblock.id, type: last.opcode === 'JUMP' ? 'jump' : 'jumpi-true' });
          } else {
            b.dynamicJump = true;
          }
        } else {
          b.dynamicJump = true;
        }
        if (last.opcode === 'JUMPI' && next) {
          b.successors.push(next.id);
          edges.push({ from: b.id, to: next.id, type: 'jumpi-false' });
        }
      } else if (last.opcode === 'STOP' || last.opcode === 'RETURN' || last.opcode === 'REVERT' || last.opcode === 'INVALID' || last.opcode === 'SELFDESTRUCT') {
        // terminal, no successors
      } else if (next) {
        b.successors.push(next.id);
        edges.push({ from: b.id, to: next.id, type: 'fallthrough' });
      }
    }

    blocks.forEach(function (b) {
      b.successors.forEach(function (s) { if (typeof s === 'number' && blocks[s]) blocks[s].predecessors.push(b.id); });
    });

    // Reachability (worklist from entry).
    var work = [0], seen = {};
    while (work.length) {
      var id = work.pop();
      if (seen[id]) continue;
      seen[id] = true;
      blocks[id].reachable = true;
      blocks[id].instructions.forEach(function (ins) { ins.reachable = true; });
      blocks[id].successors.forEach(function (s) { if (typeof s === 'number') work.push(s); });
    }

    // Reachability classification: REACHABLE / MAYBE_REACHABLE / UNREACHABLE.
    // MAYBE_REACHABLE = a JUMPDEST-start block not statically reachable (a
    // potential dynamic-jump target). UNREACHABLE = neither reachable nor a
    // potential jump target.
    blocks.forEach(function (b) {
      if (b.reachable) b.reach = 'REACHABLE';
      else if (b.id === 0) b.reach = 'REACHABLE';
      else if (jumpdests[b.startPc]) b.reach = 'MAYBE_REACHABLE';
      else { b.reach = 'UNREACHABLE'; b.dead = true; }
    });
    instructions.forEach(function (ins) {
      if (ins.reachable !== true) ins.reachable = false;
      ins.reach = blocks[ins.block] ? blocks[ins.block].reach : 'UNREACHABLE';
      ins.dead = blocks[ins.block] ? blocks[ins.block].dead : false;
    });

    var staticJumps = 0, dynamicJumps = 0, reachableIns = 0, maybeIns = 0, deadIns = 0;
    blocks.forEach(function (b) {
      if (b.terminator === 'JUMP' || b.terminator === 'JUMPI') { if (b.dynamicJump) dynamicJumps++; else staticJumps++; }
    });
    instructions.forEach(function (ins) {
      if (ins.reach === 'REACHABLE') reachableIns++;
      else if (ins.reach === 'MAYBE_REACHABLE') maybeIns++;
      else deadIns++;
    });

    return {
      blocks: blocks,
      edges: edges,
      entryBlock: 0,
      stats: {
        blocks: blocks.length,
        edges: edges.length,
        reachableInstructions: reachableIns,
        maybeReachableInstructions: maybeIns,
        deadInstructions: deadIns,
        staticJumps: staticJumps,
        dynamicJumps: dynamicJumps
      }
    };
  }

  // Detect `CALLER`/`ORIGIN` … `EQ` … `JUMPI` (weak access-control gate signal).
  function hasConditionalGate(instructions, opcode) {
    for (var i = 0; i < instructions.length; i++) {
      if (instructions[i].opcode !== opcode) continue;
      for (var j = i + 1; j < instructions.length && j <= i + 8; j++) {
        if (instructions[j].opcode === 'EQ') {
          for (var k = j + 1; k < instructions.length && k <= j + 4; k++) {
            if (instructions[k].opcode === 'JUMPI') return true;
          }
        }
      }
    }
    return false;
  }

  // Detect function selectors via the dispatcher pattern `PUSH4 <sel> EQ … JUMPI`.
  function analyzeSelectorDispatcher(blocks) {
    var map = {};
    for (var bi = 0; bi < blocks.length; bi++) {
      var b = blocks[bi];
      if (b.dead) continue;
      for (var ii = 0; ii < b.instructions.length; ii++) {
        var ins = b.instructions[ii];
        if (ins.opcode !== 'PUSH4' || ins.argument.length !== 8) continue;
        var sawEq = false, foundJumpi = false;
        for (var jj = ii + 1; jj < b.instructions.length && jj <= ii + 6; jj++) {
          var opj = b.instructions[jj].opcode;
          if (opj === 'EQ') sawEq = true;
          else if (opj === 'JUMPI' && sawEq) { foundJumpi = true; break; }
          else if (isTerminator(opj)) break;
        }
        if (!foundJumpi) continue;
        var sel = ins.argument;
        map[sel] = {
          selector: '0x' + sel,
          name: KNOWN_SELECTOR_NAMES[sel] || 'UNKNOWN',
          entryPc: (b.jumpTargetPc !== null) ? b.jumpTargetPc : null,
          confidence: (b.jumpTargetPc !== null) ? 'HIGH' : 'MEDIUM'
        };
      }
    }
    return map;
  }

  // ── 2c. Data-Flow Analysis ──────────────────────────────────────────────────
  var DF_LIMITS = {
    MAX_BLOCKS: 4000,
    MAX_PATHS: 256,
    MAX_DEPTH: 64,
    MAX_ITERATIONS: 200000,
    MAX_STACK_DEPTH: 512
  };

  function dfDescribe(v) {
    if (!v) return { known: false, value: null, source: 'UNKNOWN' };
    if (v.k === 'const') return { known: true, value: '0x' + v.v.toString(16), source: v.source };
    return { known: false, value: null, source: v.source || 'UNKNOWN' };
  }

  function dfDepsOf(v) { return (v && v.deps) ? v.deps : []; }

  // Symbolic stack executor WITH provenance. Pops/pushes carry a `source` and
  // dependency list. Unsupported opcodes propagate UNKNOWN (never guessed).
  // When `ev` is provided, storage/comparison/call events are recorded there.
  function execBlockStackDF(list, ev) {
    var stack = [];
    var vals = 0;
    function push(v) { if (stack.length >= DF_LIMITS.MAX_STACK_DEPTH) { stack.pop(); } stack.push(v); vals++; }
    function mkConst(v, source, pc) { return { k: 'const', v: toBig(v), source: source, deps: [pc] }; }
    function mkUnk(source, pc) { return { k: 'unknown', v: null, source: source, deps: [pc] }; }
    function derived(op, a, b, pc) {
      if (a && b && a.k === 'const' && b.k === 'const') {
        var r;
        if (op === 'ADD') r = a.v + b.v; else if (op === 'MUL') r = a.v * b.v;
        else if (op === 'SUB') r = b.v - a.v; else if (op === 'AND') r = a.v & b.v;
        else if (op === 'OR') r = a.v | b.v; else if (op === 'XOR') r = a.v ^ b.v;
        else if (op === 'SHL') r = b.v << a.v; else if (op === 'SHR') r = b.v >> a.v;
        else if (op === 'DIV') r = (a.v === BigInt(0) ? BigInt(0) : b.v / a.v);
        else if (op === 'MOD') r = (a.v === BigInt(0) ? BigInt(0) : b.v % a.v);
        return { k: 'const', v: r, source: 'DERIVED', deps: dfDepsOf(a).concat(dfDepsOf(b), [pc]) };
      }
      return { k: 'unknown', v: null, source: 'DERIVED', deps: dfDepsOf(a).concat(dfDepsOf(b), [pc]) };
    }

    for (var i = 0; i < list.length; i++) {
      var ins = list[i], op = ins.opcode, m;
      if (op === 'PUSH0') { push(mkConst(0, 'PUSH', ins.pc)); continue; }
      if ((m = /^PUSH(\d+)$/.exec(op))) {
        var n = parseInt(m[1], 10);
        if (ins.argument.length === 2 * n) push(mkConst('0x' + ins.argument, 'PUSH', ins.pc));
        else push(mkUnk('PUSH', ins.pc));
        continue;
      }
      if ((m = /^DUP(\d+)$/.exec(op))) { var dn = parseInt(m[1], 10); push(stack.length >= dn ? stack[stack.length - dn] : mkUnk('UNKNOWN', ins.pc)); continue; }
      if ((m = /^SWAP(\d+)$/.exec(op))) {
        var sn = parseInt(m[1], 10);
        if (stack.length >= sn + 1) { var top = stack.pop(); var idx = stack.length - sn; var other = stack[idx]; stack[idx] = top; stack.push(other); }
        else { for (var k2 = 0; k2 < stack.length; k2++) stack[k2] = mkUnk('UNKNOWN', ins.pc); }
        continue;
      }
      if (op === 'POP') { stack.pop(); continue; }
      if (op === 'CALLER') { push(mkUnk('CALLER', ins.pc)); continue; }
      if (op === 'ORIGIN') { push(mkUnk('ORIGIN', ins.pc)); continue; }
      if (op === 'CALLVALUE') { push(mkUnk('CALLVALUE', ins.pc)); continue; }
      if (op === 'CALLDATASIZE') { push(mkUnk('CALLDATASIZE', ins.pc)); continue; }
      if (op === 'ADDRESS') { push(mkUnk('ADDRESS', ins.pc)); continue; }
      if (op === 'BALANCE') { stack.pop(); push(mkUnk('BALANCE', ins.pc)); continue; }
      if (op === 'TIMESTAMP') { push(mkUnk('TIMESTAMP', ins.pc)); continue; }
      if (op === 'NUMBER') { push(mkUnk('NUMBER', ins.pc)); continue; }
      if (op === 'CHAINID') { push(mkUnk('CHAINID', ins.pc)); continue; }
      if (op === 'GAS') { push(mkUnk('GAS', ins.pc)); continue; }
      if (op === 'CALLDATALOAD') { stack.pop(); push(mkUnk('CALLDATALOAD', ins.pc)); continue; }
      if (op === 'ADD' || op === 'MUL' || op === 'SUB' || op === 'AND' || op === 'OR' || op === 'XOR' || op === 'SHL' || op === 'SHR' || op === 'DIV' || op === 'MOD') {
        var a = stack.pop(), b = stack.pop();
        push(derived(op, a, b, ins.pc));
        continue;
      }
      if (op === 'EQ' || op === 'LT' || op === 'GT') {
        var e1 = stack.pop(), e2 = stack.pop();
        var evRes = derived('EQ', e1, e2, ins.pc); // reuse const-folding for comparison value
        if (op === 'LT' || op === 'GT') {
          var lv = (e1 && e2 && e1.k === 'const' && e2.k === 'const') ? (op === 'LT' ? (e2.v < e1.v) : (e2.v > e1.v)) : null;
          evRes = (lv === null) ? mkUnk('DERIVED', ins.pc) : mkConst(lv ? 1 : 0, 'DERIVED', ins.pc);
          evRes.deps = dfDepsOf(e1).concat(dfDepsOf(e2), [ins.pc]);
        }
        push(evRes);
        if (ev) {
          ev.comparisons.push({ opcode: op, pc: ins.pc, blockId: ins.block, reach: ins.reach, left: dfDescribe(e1), right: dfDescribe(e2) });
          ev.events.push({ type: 'comparison', opcode: op, pc: ins.pc, blockId: ins.block, reach: ins.reach });
        }
        continue;
      }
      if (op === 'SLOAD') {
        var slotVal = stack.pop();
        var d = dfDescribe(slotVal);
        var slotKey = d.known ? d.value : null;
        if (ev) {
          ev.storageReads.push({ type: 'storage-read', pc: ins.pc, blockId: ins.block, reach: ins.reach, slot: d.known ? d.value : 'UNKNOWN', slotKey: slotKey, value: 'STORAGE', valueKnown: false, confidence: d.known ? 'HIGH' : 'LOW' });
          ev.events.push({ type: 'storage-read', pc: ins.pc, blockId: ins.block, reach: ins.reach, slot: d.known ? d.value : 'UNKNOWN', slotKey: slotKey });
        }
        push(mkUnk('SLOAD', ins.pc));
        continue;
      }
      if (op === 'SSTORE') {
        var wv = stack.pop(); var ws = stack.pop();
        var wd = dfDescribe(ws), vd = dfDescribe(wv);
        var wkey = wd.known ? wd.value : null;
        if (ev) {
          ev.storageWrites.push({ type: 'storage-write', pc: ins.pc, blockId: ins.block, reach: ins.reach, slot: wd.known ? wd.value : 'UNKNOWN', slotKey: wkey, value: vd.known ? vd.value : 'UNKNOWN', valueKnown: vd.known, confidence: wd.known ? 'HIGH' : 'LOW' });
          ev.events.push({ type: 'storage-write', pc: ins.pc, blockId: ins.block, reach: ins.reach, slot: wd.known ? wd.value : 'UNKNOWN', slotKey: wkey, value: vd.known ? vd.value : 'UNKNOWN', valueKnown: vd.known });
        }
        continue;
      }
      if (op === 'CALL' || op === 'CALLCODE') {
        var n7 = 7, targetIdx = 6, valueIdx = 5;
        var tgt = (stack.length >= targetIdx) ? dfDescribe(stack[stack.length - targetIdx]) : { known: false, value: null, source: 'UNKNOWN' };
        var val = (stack.length >= valueIdx + 1) ? dfDescribe(stack[stack.length - (valueIdx + 1)]) : { known: false, value: null, source: 'UNKNOWN' };
        for (var c7 = 0; c7 < n7 && stack.length; c7++) stack.pop();
        if (ev) {
          ev.externalCalls.push({ opcode: op, pc: ins.pc, blockId: ins.block, reach: ins.reach, target: tgt.known ? tgt.value : 'UNKNOWN', targetKnown: tgt.known, value: val.known ? val.value : 'UNKNOWN', valueKnown: val.known, confidence: 'MEDIUM' });
          ev.events.push({ type: 'external-call', opcode: op, pc: ins.pc, blockId: ins.block, reach: ins.reach, slotKey: null });
        }
        continue;
      }
      if (op === 'DELEGATECALL' || op === 'STATICCALL') {
        var n6 = 6, tidx6 = 5;
        var tgt6 = (stack.length >= tidx6) ? dfDescribe(stack[stack.length - tidx6]) : { known: false, value: null, source: 'UNKNOWN' };
        for (var c6 = 0; c6 < n6 && stack.length; c6++) stack.pop();
        if (ev) {
          ev.externalCalls.push({ opcode: op, pc: ins.pc, blockId: ins.block, reach: ins.reach, target: tgt6.known ? tgt6.value : 'UNKNOWN', targetKnown: tgt6.known, value: 'UNKNOWN', valueKnown: false, confidence: 'MEDIUM' });
          ev.events.push({ type: 'external-call', opcode: op, pc: ins.pc, blockId: ins.block, reach: ins.reach, slotKey: null });
        }
        continue;
      }
      // Any other opcode: unknown stack effect → invalidate (never guess).
      for (var k3 = 0; k3 < stack.length; k3++) stack[k3] = mkUnk('UNKNOWN', ins.pc);
    }
    if (ev) ev.values = (ev.values || 0) + vals;
    return stack;
  }

  function walkPaths(cfg, eventsByBlock, limits) {
    var paths = [];
    var iterations = 0;
    function dfs(blockId, visited, path, depth) {
      if (paths.length >= limits.MAX_PATHS || depth > limits.MAX_DEPTH || iterations > limits.MAX_ITERATIONS) return;
      iterations++;
      if (visited[blockId]) return; // loop back-edge: stop (avoid infinite)
      var block = cfg.blocks[blockId];
      if (!block) return;
      var nv = {}; for (var k in visited) nv[k] = visited[k]; nv[blockId] = true;
      var blkEvents = (eventsByBlock[blockId] && eventsByBlock[blockId].events) || [];
      var newPath = path.concat(blkEvents);
      var succ = block.successors.filter(function (s) { return typeof s === 'number'; });
      if (!succ.length) { paths.push(newPath); return; }
      for (var i = 0; i < succ.length; i++) dfs(succ[i], nv, newPath, depth + 1);
    }
    dfs(cfg.entryBlock, {}, [], 0);
    return { paths: paths, iterations: iterations, hitLimit: paths.length >= limits.MAX_PATHS || iterations > limits.MAX_ITERATIONS };
  }

  function reentrancyRank(cls) { return cls === 'LIKELY' ? 2 : cls === 'POTENTIAL' ? 1 : 0; }
  function maxReentrancy(a, b) { return reentrancyRank(a) >= reentrancyRank(b) ? a : b; }

  function analyzeReentrancy(paths) {
    var classification = 'NONE';
    var patterns = [];
    var guard = { detected: false, confidence: 'LOW', evidence: [] };
    var cei = { effectsBeforeInteractions: 0, interactionsBeforeEffects: 0, unknown: 0 };

    paths.forEach(function (path) {
      var readSlots = {};   // slotKey -> read pc
      var lockedSlot = null;
      for (var i = 0; i < path.length; i++) {
        var e = path[i];
        if (e.type === 'storage-read' && e.slotKey) readSlots[e.slotKey] = e.pc;
        if (e.type === 'storage-write' && e.slotKey && e.valueKnown && e.value === '0x1') lockedSlot = e.slotKey;
        if (e.type === 'external-call' && (e.opcode === 'CALL' || e.opcode === 'DELEGATECALL')) {
          var wroteAfter = false, wroteReadSlotAfter = false, unlockAfter = false;
          for (var j = i + 1; j < path.length; j++) {
            var w = path[j];
            if (w.type === 'external-call') break;
            if (w.type === 'storage-write') {
              wroteAfter = true;
              if (w.slotKey && readSlots[w.slotKey]) {
                wroteReadSlotAfter = true;
                classification = maxReentrancy(classification, 'LIKELY');
                patterns.push({ kind: 'read-call-write', slot: w.slotKey, readPc: readSlots[w.slotKey], callPc: e.pc, writePc: w.pc });
              }
            }
            if (lockedSlot && w.type === 'storage-write' && w.slotKey === lockedSlot && w.valueKnown && w.value === '0x0') unlockAfter = true;
          }
          if (wroteAfter && !wroteReadSlotAfter) {
            classification = maxReentrancy(classification, 'POTENTIAL');
            patterns.push({ kind: 'call-then-write', callPc: e.pc });
          }
          if (lockedSlot && unlockAfter) {
            guard.detected = true; guard.confidence = 'MEDIUM';
            guard.evidence.push({ slot: lockedSlot, callPc: e.pc });
          }
        }
      }
      // CEI ordering (per path, block-level): count write-before-call vs call-before-write.
      var writesBeforeCall = 0, writesAfterCall = 0;
      var seenCall = false;
      path.forEach(function (e) {
        if (e.type === 'storage-write') { if (seenCall) writesAfterCall++; else writesBeforeCall++; }
        if (e.type === 'external-call') seenCall = true;
      });
      if (writesBeforeCall && !writesAfterCall) cei.effectsBeforeInteractions++;
      else if (writesAfterCall && !writesBeforeCall) cei.interactionsBeforeEffects++;
      else if (writesBeforeCall || writesAfterCall) cei.unknown++;
    });

    return { classification: classification, patterns: patterns, guard: guard, cei: cei };
  }

  function analyzeDataFlow(cfg) {
    var blocks = cfg.blocks;
    var limits = DF_LIMITS;
    var res = {
      completeness: 'COMPLETE',
      storageReads: [], storageWrites: [], externalCalls: [], comparisons: [],
      controlDependencies: [], accessControl: [], callOrdering: [],
      reentrancy: { classification: 'NONE', patterns: [] },
      reentrancyGuard: { detected: false, confidence: 'LOW', evidence: [] },
      cei: { effectsBeforeInteractions: 0, interactionsBeforeEffects: 0, unknown: 0 },
      values: 0,
      limitsHit: false
    };

    if (blocks.length > limits.MAX_BLOCKS) { res.completeness = 'PARTIAL'; res.limitsHit = true; return res; }

    var eventsByBlock = [];
    for (var bi = 0; bi < blocks.length; bi++) {
      var b = blocks[bi];
      if (b.reach === 'UNREACHABLE') { eventsByBlock.push({ comparisons: [], storageReads: [], storageWrites: [], externalCalls: [], events: [], values: 0 }); continue; }
      var ev = { comparisons: [], storageReads: [], storageWrites: [], externalCalls: [], events: [], values: 0 };
      execBlockStackDF(b.instructions, ev);
      eventsByBlock.push(ev);
      ev.storageReads.forEach(function (e) { res.storageReads.push(e); });
      ev.storageWrites.forEach(function (e) { res.storageWrites.push(e); });
      ev.externalCalls.forEach(function (e) { res.externalCalls.push(e); });
      ev.comparisons.forEach(function (e) { res.comparisons.push(e); });
      res.values += ev.values;
    }

    // Access control: comparisons involving CALLER that gate a JUMPI.
    var jumpiBlocks = {};
    blocks.forEach(function (b) {
      if (b.terminator === 'JUMPI') {
        // find comparison in this block involving CALLER
        var evB = eventsByBlock[b.id] || {};
        (evB.comparisons || []).forEach(function (c) {
          var srcs = [c.left.source, c.right.source];
          if (srcs.indexOf('CALLER') !== -1) {
            var other = (c.left.source === 'CALLER') ? c.right : c.left;
            res.accessControl.push({
              protectedBy: [{ source: 'CALLER', comparison: c.opcode, value: other.known ? other.value : 'UNKNOWN' }],
              pc: c.pc, blockId: b.id, confidence: other.known ? 'MEDIUM' : 'LOW'
            });
          }
        });
      }
    });

    // Control dependencies: a block that is the jump-true target of a JUMPI
    // block inherits that block's comparison as a control dependency.
    blocks.forEach(function (b) {
      b.successors.forEach(function (s) {
        if (typeof s !== 'number') return;
        var pred = blocks[b.id];
        if (pred.terminator === 'JUMPI' && pred.jumpTargetPc !== null && blocks[s].startPc === pred.jumpTargetPc) {
          var evP = eventsByBlock[b.id] || {};
          (evP.comparisons || []).forEach(function (c) {
            res.controlDependencies.push({
              pc: blocks[s].startPc, blockId: s,
              gatedBy: (c.left.source === 'CALLER' || c.right.source === 'CALLER')
                ? ('CALLER ' + c.opcode + ' ' + ((c.left.source === 'CALLER') ? c.right.value : c.left.value))
                : ('cond@' + c.pc)
            });
          });
        }
      });
    });

    // Path-based CEI + reentrancy.
    var walk = walkPaths(cfg, eventsByBlock, limits);
    var re = analyzeReentrancy(walk.paths);
    res.reentrancy = { classification: re.classification, patterns: re.patterns };
    res.reentrancyGuard = re.guard;
    res.cei = re.cei;
    res.callOrdering = res.storageReads.concat(res.storageWrites, res.externalCalls);
    if (walk.hitLimit || blocks.length >= limits.MAX_BLOCKS) { res.completeness = 'PARTIAL'; res.limitsHit = true; }
    else if (cfg.stats.dynamicJumps > 0) { res.completeness = 'PARTIAL'; }

    res.stats = {
      storageReads: res.storageReads.length,
      storageWrites: res.storageWrites.length,
      externalCalls: res.externalCalls.length,
      comparisons: res.comparisons.length,
      controlDependencies: res.controlDependencies.length,
      accessControl: res.accessControl.length,
      values: res.values,
      paths: walk.paths.length
    };
    return res;
  }

  // ── 2d. Interprocedural Analysis + Evidence Graph ──────────────────────────
  function fnv1a32(str, seed) {
    var h = (seed === undefined) ? 0x811c9dc5 : seed;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 0x01000193) >>> 0;
    }
    return h >>> 0;
  }

  // Deterministic (non-cryptographic) fingerprint of the bytecode hex.
  function bytecodeHash(hex) {
    var s = hex || '';
    var a = fnv1a32(s, 0x811c9dc5);
    var b = fnv1a32(s.split('').reverse().join(''), 0x01000193);
    function h8(n) { return ('0000000' + n.toString(16)).slice(-8); }
    return '0x' + h8(a) + h8(b);
  }

  function blockIdAtPc(cfg, pc) {
    for (var i = 0; i < cfg.blocks.length; i++) {
      var b = cfg.blocks[i];
      if (pc >= b.startPc && pc < (b.endPc || (b.startPc + 1))) return b.id;
    }
    return null;
  }

  function buildFunctionGraph(cfg, functionMap) {
    var nodes = [], edges = [];
    var fns = [];
    Object.keys(functionMap).forEach(function (sel) {
      var f = functionMap[sel];
      if (f.entryPc !== null && f.entryPc !== undefined) fns.push({ selector: f.selector, name: f.name, entryPc: f.entryPc, confidence: f.confidence });
    });
    fns.sort(function (a, b) { return a.entryPc - b.entryPc; });

    var entryToId = {};
    fns.forEach(function (f, i) {
      var id = 'fn_' + i;
      nodes.push({ id: id, selector: f.selector, name: f.name, entryPc: f.entryPc, entryBlock: blockIdAtPc(cfg, f.entryPc), confidence: f.confidence, reachability: 'REACHABLE' });
      entryToId[f.entryPc] = id;
    });

    // Function ownership per block (last function entry <= block start).
    var blockFn = {};
    cfg.blocks.forEach(function (b) {
      var owner = null;
      for (var i = 0; i < fns.length; i++) {
        if (fns[i].entryPc <= b.startPc) owner = entryToId[fns[i].entryPc];
        else break;
      }
      blockFn[b.id] = owner;
    });

    cfg.blocks.forEach(function (b) {
      var fromFn = blockFn[b.id];
      if (b.terminator === 'JUMP' || b.terminator === 'JUMPI') {
        if (b.jumpTargetPc !== null && entryToId[b.jumpTargetPc]) {
          var toFn = entryToId[b.jumpTargetPc];
          edges.push({ from: fromFn, to: toFn, type: 'INTERNAL', pc: b.jumpTargetPc, blockId: b.id, confidence: 'HIGH' });
        } else if (b.dynamicJump) {
          edges.push({ from: fromFn, to: 'UNKNOWN', type: 'DYNAMIC', pc: null, blockId: b.id, confidence: 'LOW' });
        }
      }
    });

    return { nodes: nodes, edges: edges, blockFn: blockFn, entryToId: entryToId };
  }

  function buildStorageGraph(dataFlow) {
    var slots = [];
    var slotSet = {};
    dataFlow.storageReads.concat(dataFlow.storageWrites).forEach(function (e) {
      if (e.slotKey && !slotSet[e.slotKey]) { slotSet[e.slotKey] = true; slots.push(e.slotKey); }
    });
    slots.sort();

    var reads = dataFlow.storageReads.filter(function (e) { return e.slotKey; });
    var writes = dataFlow.storageWrites.filter(function (e) { return e.slotKey; });

    // Dependencies within the same slot, ordered by pc.
    var dependencies = [];
    slots.forEach(function (slot) {
      var evs = dataFlow.storageReads.concat(dataFlow.storageWrites)
        .filter(function (e) { return e.slotKey === slot; })
        .sort(function (a, b) { return a.pc - b.pc; });
      for (var i = 0; i + 1 < evs.length; i++) {
        var a = evs[i], b = evs[i + 1];
        var type;
        if (a.type === 'storage-write' && b.type === 'storage-read') type = 'WRITE_TO_READ';
        else if (a.type === 'storage-write' && b.type === 'storage-write') type = 'WRITE_TO_WRITE';
        else type = 'READ_TO_READ';
        dependencies.push({ type: type, slot: slot, fromPc: a.pc, toPc: b.pc, confidence: 'HIGH' });
      }
    });

    return { slots: slots, reads: reads, writes: writes, dependencies: dependencies };
  }

  function buildFunctionSummaries(cfg, functionMap, functionGraph, dataFlow) {
    var summaries = {};
    functionGraph.nodes.forEach(function (n) {
      var entryPc = null;
      Object.keys(functionMap).forEach(function (sel) { if (functionMap[sel].entryPc === n.entryPc) entryPc = functionMap[sel].entryPc; });
      var blockIds = [];
      cfg.blocks.forEach(function (b) { if (blockIdAtPc(cfg, n.entryPc) === b.id || b.startPc >= n.entryPc) { /* simplistic: blocks >= entry */ } });
      // Determine owned blocks: blocks whose startPc >= entryPc and < next entry.
      var nextEntry = Infinity;
      functionGraph.nodes.forEach(function (m) { if (m.entryPc > n.entryPc && m.entryPc < nextEntry) nextEntry = m.entryPc; });
      var ownedBlocks = cfg.blocks.filter(function (b) { return b.startPc >= n.entryPc && b.startPc < nextEntry; });

      var reads = [], writes = [], externalCalls = [], conditions = [];
      ownedBlocks.forEach(function (b) {
        dataFlow.storageReads.forEach(function (r) { if (r.blockId === b.id) reads.push(r.slot); });
        dataFlow.storageWrites.forEach(function (w) { if (w.blockId === b.id) writes.push(w.slot); });
        dataFlow.externalCalls.forEach(function (c) { if (c.blockId === b.id) externalCalls.push(c.opcode); });
        dataFlow.comparisons.forEach(function (c) { if (c.blockId === b.id) conditions.push(c.pc); });
      });
      summaries[n.id] = {
        functionId: n.id,
        selector: n.selector,
        entryPc: n.entryPc,
        reads: reads,
        writes: writes,
        internalCalls: functionGraph.edges.filter(function (e) { return e.from === n.id; }).map(function (e) { return e.to; }),
        externalCalls: externalCalls,
        conditions: conditions,
        guards: [],
        confidence: n.confidence
      };
    });
    return summaries;
  }

  function buildEvidenceGraph(cfg, functionMap, dataFlow, findings, functionGraph) {
    var nodes = [], edges = [];
    var idSeq = 0;
    function nid(prefix) { idSeq++; return prefix + '_' + idSeq; }

    // FUNCTION nodes
    var fnNode = {};
    functionGraph.nodes.forEach(function (n) {
      fnNode[n.id] = n.id;
      nodes.push({ id: n.id, type: 'FUNCTION', selector: n.selector, entryPc: n.entryPc });
    });

    // STORAGE_SLOT nodes
    var slotNode = {};
    var slotSet = {};
    dataFlow.storageReads.concat(dataFlow.storageWrites).forEach(function (e) {
      if (e.slotKey && !slotSet[e.slotKey]) {
        slotSet[e.slotKey] = true;
        var sid = 'slot_' + e.slotKey.replace('0x', '');
        slotNode[e.slotKey] = sid;
        nodes.push({ id: sid, type: 'STORAGE_SLOT', slot: e.slotKey });
      }
    });

    // EXTERNAL_CALL nodes
    dataFlow.externalCalls.forEach(function (c) {
      var id = 'call_' + c.pc;
      nodes.push({ id: id, type: 'EXTERNAL_CALL', opcode: c.opcode, pc: c.pc });
      var owner = functionGraph.blockFn[c.blockId];
      if (owner) edges.push({ from: owner, to: id, type: 'CALLS', pc: c.pc });
    });

    // BASIC_BLOCK nodes
    cfg.blocks.forEach(function (b) {
      nodes.push({ id: 'blk_' + b.id, type: 'BASIC_BLOCK', startPc: b.startPc, reach: b.reach });
    });

    // CONDITION nodes
    dataFlow.comparisons.forEach(function (c) {
      var id = 'cond_' + c.pc;
      nodes.push({ id: id, type: 'CONDITION', opcode: c.opcode, pc: c.pc });
      var owner = functionGraph.blockFn[c.blockId];
      if (owner) edges.push({ from: owner, to: id, type: 'USES', pc: c.pc });
    });

    // READ/WRITE edges (function -> slot)
    dataFlow.storageReads.forEach(function (r) {
      if (!r.slotKey) return;
      var owner = functionGraph.blockFn[r.blockId];
      if (owner && slotNode[r.slotKey]) edges.push({ from: owner, to: slotNode[r.slotKey], type: 'READS', pc: r.pc });
    });
    dataFlow.storageWrites.forEach(function (w) {
      if (!w.slotKey) return;
      var owner = functionGraph.blockFn[w.blockId];
      if (owner && slotNode[w.slotKey]) edges.push({ from: owner, to: slotNode[w.slotKey], type: 'WRITES', pc: w.pc });
    });

    // FINDING nodes + DEPENDS_ON edges (to external-call / storage slots referenced in dataFlowEvidence)
    (findings || []).forEach(function (f) {
      var fnode = { id: f.id, type: 'FINDING', severity: f.severity, category: f.category };
      nodes.push(fnode);
      (f.dataFlowEvidence || []).forEach(function (d) {
        // best-effort: link finding to referenced external-call/slot nodes
        dataFlow.externalCalls.forEach(function (c) { if (String(d).indexOf('CALL @' + c.pc) !== -1) edges.push({ from: f.id, to: 'call_' + c.pc, type: 'DEPENDS_ON' }); });
      });
    });

    return { nodes: nodes, edges: edges };
  }

  function collectEvidenceIds(evidenceGraph) {
    var ids = {};
    (evidenceGraph.nodes || []).forEach(function (n) { ids[n.id] = true; });
    return ids;
  }

  function buildEvidenceTrace(result, findingId) {
    var finding = (result.findings || []).filter(function (f) { return f.id === findingId; })[0];
    if (!finding) return { findingId: findingId, trace: [] };
    var trace = [{ type: 'FINDING', id: finding.id, severity: finding.severity }];
    (finding.dataFlowEvidence || []).forEach(function (d) { trace.push({ type: 'DATA_FLOW', text: d }); });
    (finding.controlFlowEvidence || []).forEach(function (c) { trace.push({ type: 'CONTROL_FLOW', text: c }); });
    return { findingId: findingId, trace: trace };
  }

  function buildAuditPayload(result) {
    return {
      version: '5.0.0',
      contract: {
        address: result.contract.address,
        chainId: result.contract.chainId,
        bytecodeHash: result.bytecodeHash,
        bytecodeSize: result.contract.bytecodeSize
      },
      analysis: {
        completeness: result.analysis.completeness,
        components: result.analysis.components,
        functionGraph: result.functionGraph,
        storageGraph: result.storageGraph,
        functionSummaries: result.functionSummaries,
        dataFlow: {
          storageReads: result.dataFlow.storageReads,
          storageWrites: result.dataFlow.storageWrites,
          externalCalls: result.dataFlow.externalCalls,
          reentrancy: result.dataFlow.reentrancy,
          reentrancyGuard: result.dataFlow.reentrancyGuard
        },
        evidenceGraph: result.evidenceGraph
      },
      findings: result.findings
    };
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
      source: cfg.source || 'OBSERVED',
      dataFlowEvidence: cfg.dataFlowEvidence || [],
      controlFlowEvidence: cfg.controlFlowEvidence || []
    };
  }

  // Structured evidence for an opcode observation (UI reads kind/text; future
  // consumers read type/opcode/pc/block/reachable).
  function opEvidence(ins, label) {
    var reach = !ins.dead;
    return {
      kind: 'OBSERVED',
      type: 'opcode',
      opcode: ins.opcode,
      pc: ins.pc,
      block: ins.block,
      reachable: reach,
      text: (label || ins.opcode) + ' at PC ' + ins.pc + ' (block ' + ins.block + ', ' + (reach ? 'reachable' : 'unreachable') + ')'
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

  function normalizeCompleteness(c) {
    if (c === 'COMPLETE' || c === 'full') return 'COMPLETE';
    if (c === 'PARTIAL' || c === 'partial') return 'PARTIAL';
    return 'LIMITED'; // 'LIMITED', 'minimal', or anything else
  }

  function assessRisk(findings, completeness) {
    var comp = normalizeCompleteness(completeness);
    var score = 100;
    findings.forEach(function (f) { score -= f.scoreImpact || 0; });
    score = Math.max(0, Math.min(100, Math.round(score)));

    var level = levelFromScore(score);
    findings.forEach(function (f) {
      if (f.confidence === 'LOW') return; // weak evidence does not escalate the level
      var l = levelFromSeverity(f.severity);
      if (LEVEL_RANK[l] > LEVEL_RANK[level]) level = l;
    });

    if (comp === 'LIMITED') level = 'LIMITED ANALYSIS';

    var confidence = comp === 'COMPLETE' ? 'HIGH' : comp === 'PARTIAL' ? 'MEDIUM' : 'LOW';
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

  // Unified selector → human name (used only for *known* selectors).
  var KNOWN_SELECTOR_NAMES = {
    'a9059cbb': 'transfer(address,uint256)', '23b872dd': 'transferFrom(address,address,uint256)',
    '095ea7b3': 'approve(address,uint256)', 'dd62ed3e': 'allowance(address,address)',
    '70a08231': 'balanceOf(address)', '18160ddd': 'totalSupply()',
    '06fdde03': 'name()', '95d89b41': 'symbol()', '313ce567': 'decimals()',
    '6352211e': 'ownerOf(uint256)', '081812fc': 'getApproved(uint256)',
    'a22cb465': 'setApprovalForAll(address,bool)', 'e985e9c5': 'isApprovedForAll(address,address)',
    '42842e0e': 'safeTransferFrom(address,address,uint256)', 'b88d4fde': 'safeTransferFrom(address,address,uint256,bytes)',
    'c87b56dd': 'tokenURI(uint256)', '01ffc9a7': 'supportsInterface(bytes4)',
    '00fdd58e': 'balanceOf(address,uint256)', '4e1273f4': 'balanceOfBatch(address[],uint256[])',
    'f242432a': 'safeTransferFrom(address,address,uint256,uint256,bytes)', '2eb2c2d6': 'safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)',
    '0e89341c': 'uri(uint256)', '8da5cb5b': 'owner()', 'f2fde38b': 'transferOwnership(address)',
    '715018a6': 'renounceOwnership()', '91d14854': 'hasRole(bytes32,address)', '248a9ca3': 'getRoleAdmin(bytes32)',
    '2f2ff15d': 'grantRole(bytes32,address)', 'd547741f': 'revokeRole(bytes32,address)', '36568abe': 'renounceRole(bytes32,address)',
    '8456cb59': 'pause()', '3f4ba83a': 'unpause()',
    '40c10f19': 'mint(address,uint256)', 'a0712d68': 'mint(uint256)',
    '449a52f8': 'mintTo(address,uint256)', '156e29f6': 'mint(address,uint256)',
    '42966c68': 'burn(uint256)', '79cc6790': 'burnFrom(address,uint256)'
  };

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
        description: 'Legacy CALLCODE was observed (' + c.CALLCODE.length + 'x) in reachable code. CALLCODE executes the callee\u2019s code in the caller\u2019s context (msg.sender preserved), which is error-prone.',
        evidence: c.CALLCODE.map(function (ins) { return opEvidence(ins); }),
        recommendation: 'Prefer CALL or DELEGATECALL with explicit, audited semantics.'
      }));
    }
    var calls = c.CALL.concat(c.STATICCALL, c.DELEGATECALL);
    if (calls.length) {
      var kinds = [];
      if (c.CALL.length) kinds.push(c.CALL.length + 'x CALL');
      if (c.STATICCALL.length) kinds.push(c.STATICCALL.length + 'x STATICCALL');
      if (c.DELEGATECALL.length) kinds.push(c.DELEGATECALL.length + 'x DELEGATECALL');
      ctx.findings.push(createFinding({
        id: 'external-call-present', category: 'external-call', severity: 'INFO', confidence: 'HIGH', exploitability: 0.2,
        title: 'External calls present',
        description: 'The contract performs external calls (' + kinds.join(', ') + '). This is normal; it is NOT evidence of reentrancy on its own.',
        evidence: calls.map(function (ins) { return opEvidence(ins); }),
        recommendation: 'If state changes follow external calls, review ordering (checks-effects-interactions) for reentrancy.'
      }));
    }
  }

  function ruleSelfdestruct(ctx) {
    var all = ctx.ops.SELFDESTRUCT;
    var reachable = all.filter(function (ins) { return ins.reach === 'REACHABLE'; });
    var maybe = all.filter(function (ins) { return ins.reach === 'MAYBE_REACHABLE'; });
    if (reachable.length) {
      var hasGate = ctx.privilegeCheck;
      ctx.findings.push(createFinding({
        id: 'selfdestruct-present', category: 'selfdestruct',
        severity: 'HIGH', confidence: hasGate ? 'HIGH' : 'MEDIUM', exploitability: 0.8,
        title: 'SELFDESTRUCT opcode used (reachable)',
        description: 'SELFDESTRUCT is present in statically reachable code (' + reachable.length + 'x). The contract can destroy its own code and move its balance. Who can trigger it could not be fully determined by static analysis.',
        evidence: reachable.map(function (ins) { return opEvidence(ins); }),
        recommendation: 'Verify who can trigger selfdestruct and whether funds can be unexpectedly removed.'
      }));
    }
    if (maybe.length) {
      ctx.findings.push(createFinding({
        id: 'selfdestruct-maybe', category: 'selfdestruct',
        severity: 'MEDIUM', confidence: 'LOW', exploitability: 0.5,
        title: 'SELFDESTRUCT opcode present (maybe-reachable)',
        description: 'SELFDESTRUCT was found in a block that is only reachable via a dynamic jump (jump table) — it may or may not execute.',
        evidence: maybe.map(function (ins) { return opEvidence(ins, 'maybe-reachable SELFDESTRUCT'); }),
        recommendation: 'Confirm whether this code path is actually reachable at runtime.'
      }));
    }
  }

  function ruleTxOrigin(ctx) {
    var origins = ctx.ops.ORIGIN;
    if (!origins.length) return;
    var auth = ctx.originGate;
    ctx.findings.push(createFinding({
      id: 'tx-origin-usage', category: 'tx-origin', severity: auth ? 'HIGH' : 'MEDIUM', confidence: 'MEDIUM', exploitability: 0.8,
      title: auth ? 'tx.origin used in authorization-like comparison' : 'tx.origin usage detected',
      description: 'The ORIGIN opcode (tx.origin) was observed ' + origins.length + 'x in reachable code' + (auth ? ', and it appears to flow into a conditional (EQ/JUMPI), suggesting it may gate authorization.' : '. Using tx.origin for authorization can be phished via malicious contracts. The actual risk depends on how the value is used, which static analysis cannot fully determine.'),
      evidence: origins.map(function (ins) { return opEvidence(ins); }),
      recommendation: 'Prefer msg.sender for authorization. If tx.origin is required, isolate it and audit its use.'
    }));
  }

  function ruleStorage(ctx) {
    var c = ctx.ops;
    if (c.SLOAD > 0 || c.SSTORE > 0) {
      ctx.findings.push(createFinding({
        id: 'storage-usage', category: 'storage', severity: 'INFO', confidence: 'HIGH', exploitability: 0,
        title: 'Stateful contract',
        description: 'Uses persistent storage (SLOAD x' + c.SLOAD + ', SSTORE x' + c.SSTORE + ') in reachable code.',
        evidence: [
          { kind: 'OBSERVED', text: 'SLOAD=' + c.SLOAD + ' SSTORE=' + c.SSTORE },
          { kind: 'UNKNOWN', text: 'storage slot meaning (Solidity layout not reconstructed)' }
        ],
        recommendation: 'None — informational.'
      }));
    }
  }

  function ruleProxy(ctx) {
    var dels = ctx.ops.DELEGATECALL;
    var hasDel = dels.length > 0;
    var impl = ctx.push32.indexOf(EIP1967_SLOTS.implementation) !== -1;
    var admin = ctx.push32.indexOf(EIP1967_SLOTS.admin) !== -1;
    var beacon = ctx.push32.indexOf(EIP1967_SLOTS.beacon) !== -1;
    var slot = impl || admin || beacon;

    var cap = ctx.capabilities.proxy;
    if (!hasDel) { cap.classification = 'UNKNOWN'; return; }

    if (slot) {
      cap.detected = true; cap.confidence = 'HIGH'; cap.classification = 'CONFIRMED';
      cap.upgradeable = (admin || beacon) ? 'Detected' : 'UNKNOWN';
      ctx.findings.push(createFinding({
        id: 'proxy-detected', category: 'proxy', severity: 'INFO', confidence: 'HIGH', exploitability: 0.3,
        title: 'Proxy pattern confirmed (EIP-1967)',
        description: 'Reachable DELEGATECALL plus an EIP-1967 slot constant (' + (impl ? 'implementation' : beacon ? 'beacon' : 'admin') + ') indicate an upgradeable proxy.',
        evidence: dels.map(function (ins) { return opEvidence(ins); }).concat([{ kind: 'OBSERVED', text: 'EIP-1967 slot constant present' }]),
        recommendation: 'Verify the implementation address and upgrade/admin controls. Upgradability is a capability, not a vulnerability by itself.'
      }));
      return;
    }

    var implCandidate = ctx.push20.filter(function (a) { return /^[0-9a-f]{40}$/.test(a) && a !== '0'.repeat(40); });
    if (implCandidate.length) {
      cap.detected = true; cap.confidence = 'MEDIUM'; cap.classification = 'LIKELY';
      cap.implementation = '0x' + implCandidate[0] + ' (inferred)';
      ctx.findings.push(createFinding({
        id: 'proxy-likely', category: 'proxy', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.25,
        title: 'Likely proxy pattern',
        description: 'Reachable DELEGATECALL and a hard-coded 20-byte address constant were observed — consistent with a proxy, but no EIP-1967 slot was found.',
        evidence: dels.map(function (ins) { return opEvidence(ins); }).concat([{ kind: 'INFERRED', text: 'possible implementation address present' }]),
        recommendation: 'Verify the implementation address manually.'
      }));
      return;
    }

    cap.detected = true; cap.confidence = 'LOW'; cap.classification = 'POTENTIAL';
    ctx.findings.push(createFinding({
      id: 'proxy-potential', category: 'proxy', severity: 'INFO', confidence: 'LOW', exploitability: 0.2,
      title: 'Potential proxy pattern',
      description: 'Reachable DELEGATECALL was observed, but no EIP-1967 slot or address constant was found — this is only a potential proxy, not confirmed.',
      evidence: dels.map(function (ins) { return opEvidence(ins); }).concat([{ kind: 'UNKNOWN', text: 'implementation address not resolved' }]),
      recommendation: 'If this is a proxy, verify the implementation address manually.'
    }));
  }

  function ruleOwnership(ctx) {
    var s = ctx.selectors;
    var ownerFn = !!s[OWNABLE_SELECTORS.owner];
    var transferFn = !!s[OWNABLE_SELECTORS.transferOwnership];
    var acHits = countHits(s, ACCESS_CONTROL_SELECTORS);

    if (ctx.abi) {
      var names = abiFnNames(ctx.abi);
      ownerFn = ownerFn || !!names['owner'];
      transferFn = transferFn || !!names['transferOwnership'];
      acHits = acHits || (hasAbiFn(ctx.abi, /grantRole|hasRole|renounceRole|revokeRole|getRoleAdmin/) ? 2 : 0);
    }

    var gate = ctx.privilegeCheck; // CALLER … EQ … JUMPI pattern

    if (ownerFn && transferFn) {
      ctx.capabilities.ownership = 'Detected';
      ctx.findings.push(createFinding({
        id: 'ownership-ownable', category: 'ownership', severity: 'INFO', confidence: 'HIGH', exploitability: 0.4,
        title: 'Ownable-style ownership detected',
        description: 'owner() and transferOwnership() selectors are present — the contract has a single privileged owner.' + (gate ? ' A CALLER-based conditional gate was also detected, consistent with owner-only access control.' : ''),
        evidence: [
          { kind: 'OBSERVED', text: 'selector owner() = 0x' + OWNABLE_SELECTORS.owner },
          { kind: 'OBSERVED', text: 'selector transferOwnership() = 0x' + OWNABLE_SELECTORS.transferOwnership },
          { kind: gate ? 'INFERRED' : 'UNKNOWN', text: gate ? 'CALLER … EQ … JUMPI privilege gate observed' : 'privilege gate not statically resolved' }
        ],
        recommendation: 'Verify what the owner can do (mint, fees, pause, upgrade). Privilege is not a flaw unless misused.'
      }));
    } else if (ownerFn) {
      ctx.capabilities.ownership = 'Potential';
      ctx.findings.push(createFinding({
        id: 'ownership-potential', category: 'ownership', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0.3,
        title: 'Potential privileged owner',
        description: 'An owner() selector was detected, but transfer/renounce controls were not identified.',
        evidence: [{ kind: 'OBSERVED', text: 'selector owner() = 0x' + OWNABLE_SELECTORS.owner }],
        recommendation: 'Determine the owner\u2019s capabilities from the source/ABI.'
      }));
    } else {
      ctx.capabilities.ownership = 'Unknown';
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
    var mintSels = [], burnSels = [], mintRawSels = [];
    MINT_SELECTORS.forEach(function (m) { if (s[m.sel]) { mintSels.push(m.label); mintRawSels.push(m.sel); } });
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
      // Conservative "potential unrestricted": requires a resolved mint entry
      // point (a dispatcher routing the selector) AND no detected auth gate /
      // ownership / access-control selectors. Absence of evidence is NOT proof.
      var ownerSig = !!ctx.selectors[OWNABLE_SELECTORS.owner] || !!ctx.selectors[OWNABLE_SELECTORS.transferOwnership];
      var acSig = countHits(ctx.selectors, ACCESS_CONTROL_SELECTORS) >= 1;
      var hasResolvedMintEntry = mintRawSels.some(function (sel) { return ctx.functionMap && ctx.functionMap[sel]; });
      if (hasResolvedMintEntry && !ctx.privilegeCheck && !ownerSig && !acSig) {
        mintCap.restriction = 'potentially unrestricted';
        ctx.findings.push(createFinding({
          id: 'mint-potential-unrestricted', category: 'mint', severity: 'MEDIUM', confidence: 'LOW', exploitability: 0.6,
          title: 'Potential unrestricted mint (no authorization gate detected)',
          description: 'A mint function is present with a resolved entry point, and no static authorization signal (ownership/access-control selectors or a CALLER-based conditional gate) was detected. This is absence-of-evidence, not proof — the mint could still be restricted by logic this analyzer cannot see.',
          evidence: [
            { kind: 'INFERRED', text: 'mint selector resolved to a function entry' },
            { kind: 'UNKNOWN', text: 'no detectable authorization path' }
          ],
          recommendation: 'Review the source to confirm mint access control before trusting the token supply.'
        }));
      }
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

  function ruleDataFlow(ctx) {
    var df = ctx.dataFlow;
    if (!df) return;

    if (df.reentrancy.classification === 'LIKELY') {
      ctx.findings.push(createFinding({
        id: 'reentrancy-pattern', category: 'reentrancy', severity: 'MEDIUM', confidence: 'MEDIUM', exploitability: 0.7,
        title: 'Potential reentrancy pattern (read → call → write same slot)',
        description: 'Data-flow found a storage slot read, followed by an external call, followed by a write to the same slot. This is a classic reentrancy shape, but is NOT confirmed (no semantic analysis of the value or of any guard).',
        evidence: [{ kind: 'INFERRED', text: 'read → call → write (same slot)' }],
        dataFlowEvidence: df.reentrancy.patterns.filter(function (p) { return p.kind === 'read-call-write'; }).map(function (p) { return 'SLOAD(' + p.slot + ') @' + p.readPc + ' → CALL @' + p.callPc + ' → SSTORE(' + p.slot + ') @' + p.writePc; }),
        recommendation: 'Verify state is updated before the external call (checks-effects-interactions), or a reentrancy guard is present and correct.'
      }));
    } else if (df.reentrancy.classification === 'POTENTIAL') {
      ctx.findings.push(createFinding({
        id: 'reentrancy-pattern', category: 'reentrancy', severity: 'LOW', confidence: 'LOW', exploitability: 0.5,
        title: 'External call followed by state write',
        description: 'Data-flow found an external call followed by a state write (interactions-before-effects). No same-slot read→write dependency was confirmed, so this is a potential, not confirmed, risk.',
        evidence: [{ kind: 'INFERRED', text: 'call then write' }],
        dataFlowEvidence: df.reentrancy.patterns.filter(function (p) { return p.kind === 'call-then-write'; }).map(function (p) { return 'CALL @' + p.callPc + ' → SSTORE'; }),
        recommendation: 'Review the ordering; prefer effects-before-interactions.'
      }));
    }

    if (df.reentrancyGuard.detected) {
      ctx.findings.push(createFinding({
        id: 'reentrancy-guard', category: 'reentrancy', severity: 'INFO', confidence: 'MEDIUM', exploitability: 0,
        title: 'Potential reentrancy guard detected',
        description: 'A storage slot appears to be set to 1 before an external call and reset to 0 after — consistent with a nonReentrant/lock pattern. Its correctness is NOT verified.',
        evidence: df.reentrancyGuard.evidence.map(function (e) { return { kind: 'INFERRED', text: 'slot ' + e.slot + ' locked around CALL @' + e.callPc }; }),
        recommendation: 'Confirm the guard covers all external calls and cannot be bypassed.'
      }));
    }

    if (df.accessControl.length) {
      ctx.findings.push(createFinding({
        id: 'access-control-gate', category: 'access-control', severity: 'INFO',
        confidence: df.accessControl[0].confidence === 'MEDIUM' ? 'MEDIUM' : 'LOW', exploitability: 0.3,
        title: 'Privileged access-control gate detected',
        description: 'A CALLER comparison feeds a conditional branch (potential authorization gate). This does not prove onlyOwner — only that a caller-check gate exists.',
        evidence: df.accessControl.map(function (ac) {
          return { kind: 'INFERRED', text: ac.protectedBy.map(function (p) { return p.source + ' ' + p.comparison + ' ' + p.value; }).join('; ') + ' @PC ' + ac.pc };
        }),
        recommendation: 'Verify the gate protects sensitive state changes (mint, fees, upgrade).'
      }));
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
      proxy: { detected: false, confidence: null, classification: 'UNKNOWN', implementation: 'UNKNOWN', admin: 'UNKNOWN', upgradeable: 'UNKNOWN' },
      upgradeability: 'UNKNOWN'
    };

    var result = {
      contract: { address: address, chainId: chainId, type: 'Unknown', bytecodeSize: 0 },
      analysis: { completeness: 'LIMITED', analyzerVersion: VERSION, timestamp: Date.now() },
      risk: { score: 100, level: 'LIMITED ANALYSIS', confidence: 'LOW' },
      findings: [],
      capabilities: cap,
      observed: [],
      inferred: [],
      unknown: [],
      functionMap: {},
      cfg: null
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
      result.risk = assessRisk(result.findings, 'LIMITED');
      return result;
    }

    if (hex === '') {
      result.contract.type = 'EOA';
      result.risk = assessRisk(result.findings, 'LIMITED');
      return result;
    }

    var dis = disassemble(hex);
    var bodyLen = hex.length / 2;
    result.contract.bytecodeSize = bodyLen;
    result.bytecodeHash = bytecodeHash(hex);
    result.analysisVersion = '5.0.0';

    // Control-flow analysis.
    var cfg = buildCfg(dis.instructions);
    result.cfg = cfg.stats;

    // Data-flow analysis.
    var dataFlow = analyzeDataFlow(cfg);
    result.dataFlow = dataFlow;

    var truncated = false;
    dis.instructions.forEach(function (ins) { if (ins.truncated) truncated = true; });

    var completeness;
    if (truncated) completeness = 'LIMITED';
    else if (cfg.stats.dynamicJumps > 0) completeness = 'PARTIAL';
    else completeness = 'COMPLETE';
    result.analysis.completeness = completeness;
    result.analysis.components = {
      controlFlow: truncated ? 'LIMITED' : (cfg.stats.dynamicJumps > 0 ? 'PARTIAL' : 'COMPLETE'),
      stack: 'PARTIAL',
      dataFlow: dataFlow.completeness,
      overall: completeness
    };

    var executable = dis.instructions.filter(function (ins) { return !ins.dead; });

    // Opcode observations from *executable* instructions (objects carry pc/block/reachable).
    var ops = {
      CALL: [], CALLCODE: [], DELEGATECALL: [], STATICCALL: [],
      SELFDESTRUCT: [], CREATE: [], CREATE2: [], ORIGIN: [], CALLER: [],
      SLOAD: 0, SSTORE: 0, JUMP: 0, JUMPI: 0, JUMPDEST: 0
    };
    executable.forEach(function (ins) {
      switch (ins.opcode) {
        case 'CALL': ops.CALL.push(ins); break;
        case 'CALLCODE': ops.CALLCODE.push(ins); break;
        case 'DELEGATECALL': ops.DELEGATECALL.push(ins); break;
        case 'STATICCALL': ops.STATICCALL.push(ins); break;
        case 'SELFDESTRUCT': ops.SELFDESTRUCT.push(ins); break;
        case 'CREATE': ops.CREATE.push(ins); break;
        case 'CREATE2': ops.CREATE2.push(ins); break;
        case 'ORIGIN': ops.ORIGIN.push(ins); break;
        case 'CALLER': ops.CALLER.push(ins); break;
        case 'SLOAD': ops.SLOAD++; break;
        case 'SSTORE': ops.SSTORE++; break;
        case 'JUMP': ops.JUMP++; break;
        case 'JUMPI': ops.JUMPI++; break;
        case 'JUMPDEST': ops.JUMPDEST++; break;
      }
    });

    // Interesting opcodes in *dead* instructions (for the unreachable-code note).
    var deadOps = { SELFDESTRUCT: [], DELEGATECALL: [], CALL: [], CALLCODE: [], CREATE: [], CREATE2: [] };
    dis.instructions.forEach(function (ins) {
      if (!ins.dead) return;
      if (deadOps[ins.opcode]) deadOps[ins.opcode].push(ins);
    });

    var collected = collectSelectors(executable);
    var privilegeCheck = hasConditionalGate(executable, 'CALLER');
    var originGate = hasConditionalGate(executable, 'ORIGIN');
    var functionMap = analyzeSelectorDispatcher(cfg.blocks);
    result.functionMap = functionMap;

    // Interprocedural analysis.
    var functionGraph = buildFunctionGraph(cfg, functionMap);
    result.functionGraph = functionGraph;
    result.storageGraph = buildStorageGraph(dataFlow);
    result.functionSummaries = buildFunctionSummaries(cfg, functionMap, functionGraph, dataFlow);

    var ctx = {
      instructions: dis.instructions,
      executable: executable,
      ops: ops,
      deadOps: deadOps,
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
      unknown: result.unknown,
      privilegeCheck: privilegeCheck,
      originGate: originGate,
      functionMap: functionMap,
      dataFlow: dataFlow
    };

    // Observe (facts)
    if (ops.DELEGATECALL.length) result.observed.push('DELEGATECALL at PC ' + ops.DELEGATECALL.map(function (i) { return i.pc; }).join(','));
    if (ops.CALL.length) result.observed.push('CALL at PC ' + ops.CALL.map(function (i) { return i.pc; }).join(','));
    if (ops.SELFDESTRUCT.length) result.observed.push('SELFDESTRUCT at PC ' + ops.SELFDESTRUCT.map(function (i) { return i.pc; }).join(','));
    if (ops.ORIGIN.length) result.observed.push('ORIGIN at PC ' + ops.ORIGIN.map(function (i) { return i.pc; }).join(','));
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
    ruleDataFlow(ctx);

    // Unreachable/dead code note.
    if (cfg.stats.deadInstructions > 0) {
      var deadInteresting = [];
      Object.keys(deadOps).forEach(function (k) { if (deadOps[k].length) deadInteresting.push(deadOps[k].length + 'x ' + k); });
      ctx.findings.push(createFinding({
        id: 'unreachable-code', category: 'bytecode', severity: 'INFO', confidence: 'HIGH', exploitability: 0,
        title: 'Unreachable/dead code detected',
        description: cfg.stats.deadInstructions + ' byte(s) of the linear disassembly are not statically reachable (typically after a terminal opcode or in jump-table data).' + (deadInteresting.length ? ' Dead opcodes include: ' + deadInteresting.join(', ') + '.' : ''),
        evidence: [{ kind: 'OBSERVED', text: 'dead instructions: ' + cfg.stats.deadInstructions + ', dynamic jumps: ' + cfg.stats.dynamicJumps }],
        recommendation: 'Dead code is generally informational; verify it is not reachable via a dynamic jump.'
      }));
    }

    cap.upgradeability = cap.proxy.detected ? (cap.proxy.upgradeable === 'Detected' ? 'Detected' : 'Unknown') : 'NotDetected';

    // Sort findings by severity then confidence
    var sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    var confRank = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    result.findings.sort(function (a, b) {
      return (sevRank[a.severity] - sevRank[b.severity]) || (confRank[a.confidence] - confRank[b.confidence]);
    });

    result.evidenceGraph = buildEvidenceGraph(cfg, functionMap, dataFlow, result.findings, functionGraph);
    result.evidenceIds = collectEvidenceIds(result.evidenceGraph);

    result.risk = assessRisk(result.findings, completeness);

    // Inferred / unknown summaries (kept separate from observed facts)
    if (cap.proxy.detected) result.inferred.push('proxy pattern (' + cap.proxy.classification + ')');
    if (cap.ownership === 'Detected') result.inferred.push('Ownable-style ownership');
    if (cap.mint.present) result.inferred.push('mint capability, restriction ' + cap.mint.restriction);
    if (!abi) result.unknown.push('ABI not provided — administrative/privileged functions could not be fully enumerated');
    if (completeness === 'PARTIAL') result.unknown.push('dynamic jumps present — analysis completeness is PARTIAL');

    result.summary = buildSummary(result);
    result.analysisText = result.summary;
    result.context = buildContext(result, hex);
    result.payload = buildAuditPayload(result);

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
      s += ' This is not a guarantee of safety; it reflects only what static bytecode/ABI + control-flow analysis can observe.';
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
    buildCfg: buildCfg,
    execBlockStack: execBlockStack,
    execBlockStackDF: execBlockStackDF,
    analyzeDataFlow: analyzeDataFlow,
    resolveJumpTarget: resolveJumpTarget,
    buildFunctionGraph: buildFunctionGraph,
    buildStorageGraph: buildStorageGraph,
    buildEvidenceGraph: buildEvidenceGraph,
    buildEvidenceTrace: buildEvidenceTrace,
    buildAuditPayload: buildAuditPayload,
    bytecodeHash: bytecodeHash,
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
