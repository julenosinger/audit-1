# AuditAI

Smart-contract security scanner in a chat UI. Audit any EVM contract, scan a
wallet's portfolio, check token approvals, or compare two contracts — then
publish the result on-chain to **GenLayer**.

Live: <https://auditai-6di.pages.dev/>

## Architecture

- **`public/index.html`** — single-page app (UI + `ethers.js` EVM scanner + chat).
- **`functions/api/claude.js`** — Cloudflare Pages Function proxy to Anthropic
  (`POST /api/claude`, secret `ANTHROPIC_API_KEY`).
- **`contracts/audit_ai.py`** — GenLayer Intelligent Contract that records audit
  results as immutable on-chain state.
- **`wrangler.toml`** — Cloudflare Pages project `auditai`.

The frontend does the EVM scanning and text analysis (Claude); the GenLayer
contract is where a finished audit can be **published on-chain** and queried
later.

## Builder Journey flow

1. Star the boilerplate repo + **Verify** on the portal.
2. Add GenLayer networks + faucet **Testnet GEN**.
3. Create ≥ 1 validator at <https://studio.genlayer.com/validators>.
4. Studio → **Contracts → Add From File** → `contracts/audit_ai.py`.
5. **Run and Debug** → empty constructor → **Deploy**.
6. Copy the address → paste in the portal step "Deploy your first contract".
7. Test `publish_audit` and `get_audit` in the Studio panel.

Full step-by-step: [`contracts/README.md`](contracts/README.md).

## Local dev

```bash
npx wrangler pages dev public
```

Set `ANTHROPIC_API_KEY` as a Secret in the Cloudflare dashboard (not in code).

## Security

No API keys are committed. `ANTHROPIC_API_KEY` lives only as a Cloudflare Secret.
