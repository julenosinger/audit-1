# AuditAI

Smart-contract security scanner in a chat UI. Audit any EVM contract, scan a
wallet's portfolio, check token approvals, or compare two contracts — then
publish the result on-chain to **GenLayer**.

Live: <https://forgecontract.xyz/> (mirror: <https://auditai-6di.pages.dev/>)

## Architecture

- **`public/index.html`** — single-page app (UI + `ethers.js` EVM scanner + chat).
- **`public/local-scan.js`** — local EVM scanner (zero LLM): bytecode heuristics,
  portfolio scan, ERC-20 approval checks, static glossary.
- **`public/genlayer.js`** — GenLayer bridge: `publish_audit` / `analyze_and_publish`
  with a Studio copy-call fallback.
- **`contracts/audit_ai.py`** — GenLayer Intelligent Contract that records audit
  results on-chain. Records are mutable, caller-submitted analyses (a later
  publish overwrites the stored record; not an append-only log).

The default GenLayer transaction network is **Bradbury** (AuditAI
`0x119Ac58AF8546Df0B0E55eB24277C756d9458000`, chainId 4221); Studionet stays
available in the selector. On-chain publish/adjudicate waits for **FINALIZED**
and reads the contract state before showing an on-chain badge; the Studio
copy-call fallback (no wallet / no SDK) is explicitly **off-chain**.
- **`functions/api/claude.js`** — optional Anthropic proxy (kept for regression,
  but **not required**; disabled by default via `USE_CLAUDE = false`).
- **`wrangler.toml`** — Cloudflare Pages project `auditai`.

## LLM

AuditAI now has three paths, and **zero of them require an API key**:

1. **Local (default)** — `USE_CLAUDE = false`. All scanning is deterministic
   `ethers.js` heuristics in `public/local-scan.js`. No LLM, no external calls.
2. **GenLayer LLM** — the "Adjudicate with GenLayer LLM" button on a result card
   calls `analyze_and_publish` on the deployed Intelligent Contract. The network's
   validators run the LLM (see `contracts/README.md`). Requires a deployed contract
   + testnet GEN; otherwise it falls back to copy-call for Studio.
3. **Anthropic/Claude (flag off)** — set `USE_CLAUDE = true` and configure
   `ANTHROPIC_API_KEY` as a Cloudflare Secret to re-enable the legacy proxy. Off by
   default and never required.

## Builder Journey flow

1. Star the boilerplate repo + **Verify** on the portal.
2. Add GenLayer networks + faucet **Testnet GEN**.
3. Create ≥ 1 validator at <https://studio.genlayer.com/validators>.
4. Studio → **Contracts → Add From File** → `contracts/audit_ai.py`.
5. **Run and Debug** → empty constructor → **Deploy**.
6. Copy the address → paste in the portal step "Deploy your first contract".
7. Test `publish_audit`, `analyze_and_publish`, and `get_audit` in the Studio panel.

Full step-by-step: [`contracts/README.md`](contracts/README.md).

## Local dev

```bash
npx wrangler pages dev public
```

No secrets needed. `functions/api/claude.js` only activates if `USE_CLAUDE` is true
and `ANTHROPIC_API_KEY` is set as a Cloudflare Secret.

## Security

No API keys are committed. The app works end-to-end with local scanning + GenLayer.
