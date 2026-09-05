# AuditAI

Smart-contract security scanner in a chat UI. Audit any EVM contract, scan a
wallet's portfolio, check token approvals, or compare two contracts — then
publish the result on-chain to **GenLayer**.

Live: <https://forgecontract.xyz/> (mirror: <https://auditai-6di.pages.dev/>)

## Architecture

- **`public/index.html`** — single-page app (UI + `ethers.js` EVM scanner + chat).
- **`public/local-scan.js`** — local EVM scanner (zero LLM): bytecode heuristics,
  portfolio scan, ERC-20 approval checks, static glossary.
- **`public/genlayer.js`** — GenLayer bridge: `analyze_verified` / `publish_audit` /
  `analyze_and_publish` with a Studio copy-call fallback.
- **`contracts/audit_ai_v2.py`** — GenLayer Intelligent Contract that records audit
  results on-chain. Records are append-only and keyed by id: `analyze_verified`
  has the validators fetch the code/block themselves and binds the record to that
  fetch (`code_hash` / `block_hash` / `chain_id` / `block_number`); the legacy
  methods produce `caller_supplied` records. See [`contracts/README.md`](contracts/README.md).

The default GenLayer transaction network is **Bradbury** (AuditAI v2
`0x1BB9A3e40283808D773871a5C9F8Dc0a9711B331`, chainId 4221); Studionet stays
available in the selector. On-chain publish/adjudicate waits for **FINALIZED**
and reads the contract state before showing an on-chain badge; the Studio
copy-call fallback (no wallet / no SDK) is explicitly **off-chain**.
- **`functions/api/claude.js`** — optional Anthropic proxy (kept for regression,
  but **not required**; disabled by default via `USE_CLAUDE = false`).
- **`functions/api/chat.js`** — secure proxy for the Nemotron conversational layer
  (Phase 8). Reads the `NVIDIA_API_KEY` Cloudflare Secret server-side; the browser
  only ever calls `/api/chat`.
- **`public/nemotron-client.js` / `public/nemotron-chat.js`** — Nemotron 3.5
  Lightning conversational intelligence: normalization, validation, allowlisted
  read-only tools, and the deterministic Intent Router fallback. No API key, no
  wallet access, no transaction execution.
- **`wrangler.toml`** — Cloudflare Pages project `auditai`.

## Nemotron (Phase 8)

The Chat uses NVIDIA **Nemotron 3.5 Lightning** as its conversational/orchestration
layer (via `public/nemotron-client.js` → `functions/api/chat.js` → NVIDIA).
Nemotron never controls the wallet, never signs, never submits transactions, and
never fabricates blockchain data — the deterministic engines, the Intent Router,
and the GenLayer lifecycle remain authoritative. If NVIDIA is unavailable, the
Chat falls back to the existing deterministic router + glossary.

### NVIDIA_API_KEY (secret, server-side only)

- **Production**: set `NVIDIA_API_KEY` as a Cloudflare Secret on the `auditai`
  Pages project (Settings → Variables and Secrets → Secrets). The browser never
  receives it.
- **Local**: `npx wrangler pages dev public` and create a git-ignored
  `.dev.vars` file containing `NVIDIA_API_KEY=...`.

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
4. Studio → **Contracts → Add From File** → `contracts/audit_ai_v2.py`.
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
