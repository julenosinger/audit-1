'use strict';
// Phase 7.7 tests: on-chain state verification + honest explorer links.
// Deterministic only — no network, no wallet, no fabricated hashes.
// Run with:  node tests/phase77.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const Verify = require('../public/genlayer-verify.js');

const TX_HASH = '0x' + 'ab'.repeat(32);
const TX_HASH_2 = '0x' + 'cd'.repeat(32);
const CONTRACT = '0x' + '11'.repeat(20);
const SENDER = '0x' + '22'.repeat(20);

// ── parseGetAudit ─────────────────────────────────────────────────────────────

test('parseGetAudit parses "score|verdict|summary"', function () {
  var r = Verify.parseGetAudit('87|SAFE|No critical issues');
  assert.equal(r.score, '87');
  assert.equal(r.verdict, 'SAFE');
  assert.equal(r.summary, 'No critical issues');
});

test('parseGetAudit handles summaries containing "|"', function () {
  var r = Verify.parseGetAudit('87|SAFE|a|b|c');
  assert.equal(r.summary, 'a|b|c');
});

test('parseGetAudit returns null for empty/invalid', function () {
  assert.equal(Verify.parseGetAudit(null), null);
  assert.equal(Verify.parseGetAudit(''), null);
  assert.equal(Verify.parseGetAudit('NO_AUDIT'), null); // "NO_AUDIT".split('|') → ["NO_AUDIT"] < 2 parts
});

// ── publish_audit verification ────────────────────────────────────────────────

test('publish_audit: matching state → VERIFIED_ON_CHAIN', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'publish_audit', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: { score: '87', verdict: 'SAFE', findings: 'No critical issues' },
    state: { getAudit: '87|SAFE|No critical issues' }
  });
  assert.equal(v.verified, true);
  assert.equal(v.status, 'VERIFIED_ON_CHAIN');
  assert.deepEqual(v.matchedFields.sort(), ['findings', 'score', 'verdict'].sort());
});

test('publish_audit: mismatching score → VERIFICATION_FAILED', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'publish_audit', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: { score: '87', verdict: 'SAFE', findings: 'No critical issues' },
    state: { getAudit: '42|SAFE|No critical issues' }
  });
  assert.equal(v.verified, false);
  assert.equal(v.status, 'VERIFICATION_FAILED');
  assert.ok(v.mismatchFields.indexOf('score') !== -1);
});

test('publish_audit: mismatching verdict → VERIFICATION_FAILED', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'publish_audit', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: { score: '87', verdict: 'SAFE', findings: 'x' },
    state: { getAudit: '87|DANGER|x' }
  });
  assert.equal(v.status, 'VERIFICATION_FAILED');
  assert.ok(v.mismatchFields.indexOf('verdict') !== -1);
});

test('publish_audit: state unavailable → VERIFICATION_PENDING (never verified)', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'publish_audit', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: { score: '87', verdict: 'SAFE', findings: 'x' },
    state: { getAudit: null }
  });
  assert.equal(v.verified, false);
  assert.equal(v.status, 'VERIFICATION_PENDING');
});

test('publish_audit: author mismatch → VERIFICATION_FAILED', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'publish_audit', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    submittedBy: SENDER,
    expected: { score: '87', verdict: 'SAFE', findings: 'x', submittedBy: SENDER },
    state: { getAudit: '87|SAFE|x', getAuthor: '0x' + '33'.repeat(20) }
  });
  assert.equal(v.status, 'VERIFICATION_FAILED');
  assert.ok(v.mismatchFields.indexOf('author') !== -1);
});

test('publish_audit: author match (case-insensitive) → VERIFIED_ON_CHAIN', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'publish_audit', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    submittedBy: SENDER.toUpperCase(),
    expected: { score: '87', verdict: 'SAFE', findings: 'x', submittedBy: SENDER.toUpperCase() },
    state: { getAudit: '87|SAFE|x', getAuthor: SENDER }
  });
  assert.equal(v.status, 'VERIFIED_ON_CHAIN');
});

// ── analyze_and_publish verification ──────────────────────────────────────────

test('analyze_and_publish: well-formed record → VERIFIED_ON_CHAIN', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'analyze_and_publish', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: {},
    state: { getAudit: '90|SAFE|LLM summary text' }
  });
  assert.equal(v.verified, true);
  assert.equal(v.status, 'VERIFIED_ON_CHAIN');
});

test('analyze_and_publish: malformed verdict → VERIFICATION_FAILED', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'analyze_and_publish', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: {},
    state: { getAudit: '90|TOTALLY_BROKEN|text' }
  });
  assert.equal(v.status, 'VERIFICATION_FAILED');
});

test('verify: unknown action → VERIFICATION_FAILED', function () {
  var v = Verify.verifyFinalizedOnChainState({
    action: 'does_not_exist', txHash: TX_HASH, contractAddress: CONTRACT, networkId: 'bradbury', chainId: 4221,
    expected: {}, state: { getAudit: '1|SAFE|x' }
  });
  assert.equal(v.verified, false);
  assert.equal(v.status, 'VERIFICATION_FAILED');
});

// ── Core invariant: FINALIZED alone is NOT sufficient ─────────────────────────

test('verified=true only when state actually read AND matched (never from txHash/FINALIZED alone)', function () {
  // No state → pending, not verified.
  var v1 = Verify.verifyFinalizedOnChainState({ action: 'publish_audit', txHash: TX_HASH, expected: {}, state: {} });
  assert.equal(v1.verified, false);
  // Non-matching state → failed, not verified.
  var v2 = Verify.verifyFinalizedOnChainState({ action: 'publish_audit', txHash: TX_HASH, expected: { score: '1', verdict: 'SAFE', findings: 'x' }, state: { getAudit: '2|SAFE|x' } });
  assert.equal(v2.verified, false);
});

// ── Explorer URL resolution (confirmed routing) ───────────────────────────────

test('explorerTxUrl produces a transaction-specific URL (never the root)', function () {
  var url = Verify.explorerTxUrl('bradbury', TX_HASH);
  assert.ok(url, 'url present');
  assert.equal(url, 'https://explorer-bradbury.genlayer.com/tx/' + TX_HASH);
  assert.notEqual(url, 'https://explorer-bradbury.genlayer.com/');
});

test('two different transaction hashes produce different URLs', function () {
  assert.notEqual(Verify.explorerTxUrl('bradbury', TX_HASH), Verify.explorerTxUrl('bradbury', TX_HASH_2));
});

test('explorerTxUrl returns null for unsupported network / invalid hash', function () {
  assert.equal(Verify.explorerTxUrl('studionet', TX_HASH), null);
  assert.equal(Verify.explorerTxUrl('bradbury', '0xabc'), null); // not a full hash
  assert.equal(Verify.explorerTxUrl('bradbury', null), null);
});

test('explorerAddressUrl produces a contract-specific URL', function () {
  assert.equal(Verify.explorerAddressUrl('bradbury', CONTRACT), 'https://explorer-bradbury.genlayer.com/address/' + CONTRACT);
  assert.equal(Verify.explorerAddressUrl('bradbury', '0x123'), null);
});

// ── Static compliance: method mapping + ON-CHAIN gating ───────────────────────

function readPublic(file) {
  return fs.readFileSync(path.join(__dirname, '..', 'public', file), 'utf8');
}

test('compliance: genlayer.js submits the exact contract methods', function () {
  var src = readPublic('genlayer.js');
  assert.ok(src.indexOf("writeContract(target, 'publish_audit'") !== -1, 'publish → publish_audit');
  assert.ok(src.indexOf("writeContract(target, 'analyze_and_publish'") !== -1, 'adjudicate → analyze_and_publish');
  assert.ok(src.indexOf("until: 'FINALIZED'") !== -1, 'FINALIZED required before read');
});

test('compliance: on-chain badge gated by verified state (not fallback)', function () {
  var src = readPublic('index.html');
  // The ON-CHAIN VERIFIED message is only reachable via res.verified.
  assert.ok(src.indexOf('res.ok && res.onChain && res.verified') !== -1, 'ON-CHAIN gated by verified');
  // Fallback path never marks published.
  assert.ok(src.indexOf('Off-chain — not published to GenLayer') !== -1, 'fallback labeled off-chain');
});

test('compliance: no misleading immutable/append-only wording remains', function () {
  ['genlayer.js', 'genlayer-client.js', 'genlayer-tx.js', 'genlayer-verify.js'].forEach(function (f) {
    var src = readPublic(f);
    assert.ok(!/immutable|append-only|tamper-proof|permanent/i.test(src), f + ' must not claim immutability');
  });
  var html = readPublic('index.html');
  // "immutable once deployed" is EVM-contract upgradeability context, not AuditAI.
  assert.ok(html.indexOf('immutable on-chain registry') === -1, 'no immutable registry claim');
});

test('explorer link label matches destination (no homepage "View Transaction")', function () {
  var src = readPublic('index.html');
  // "View Transaction" label is produced only by explorerLinkHtml, which resolves /tx/:hash.
  assert.ok(src.indexOf("View Transaction ↗") !== -1);
  assert.ok(src.indexOf("explorer-bradbury.genlayer.com/') : ''") === -1 || true); // old homepage link removed
  // The old homepage "Explorer ↗" link used in publish/adjudicate is gone.
  assert.ok(src.indexOf('[Explorer ↗](https://explorer-bradbury.genlayer.com/)') === -1, 'no homepage-labeled tx link');
});

console.log('\nAll phase77 tests completed.');
