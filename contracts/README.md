# AuditAI — Intelligent Contract (GenLayer)

`contracts/audit_ai.py` is the on-chain companion to the AuditAI frontend.
It stores immutable audit records (`score`, `verdict`, `summary`) for any EVM
contract address and makes them queryable later.

## Methods

| Method | Kind | Description |
| --- | --- | --- |
| `publish_audit(contract_addr, score, verdict, findings)` | write | Deterministic, no LLM. Publishes an off-chain result. Use this for the first deploy. |
| `analyze_and_publish(contract_addr, source_or_context)` | write | GenLayer-native: LLM adjudication via `gl.eq_principle.prompt_non_comparative`. |
| `get_audit(contract_addr)` | view | `"{score}|{verdict}|{summary}"` or `"NO_AUDIT"`. |
| `get_score(contract_addr)` | view | `"0".."100"`. |
| `get_verdict(contract_addr)` | view | `SAFE | WARNING | DANGER`. |
| `get_author(contract_addr)` | view | sender hex that published. |
| `has_audit(contract_addr)` | view | `bool`. |

## Deploy in GenLayer Studio

1. Finish the portal step **"Star the Boilerplate repo"** and click **Verify**.
2. Add GenLayer networks (Studio / Asimov / Bradbury) to your wallet and get
   **Testnet GEN** from the faucet.
3. Open <https://studio.genlayer.com/validators> and create **≥ 1 validator**
   (choose a provider + model, stake ≥ 1 GEN).
4. Open <https://studio.genlayer.com/> → **Contracts** → **Add From File** →
   select `contracts/audit_ai.py`.
5. Open the file → **Run and Debug** → leave the constructor empty → **Deploy**.
6. Copy the deployed **contract address** and paste it into the portal step
   **"Deploy your first contract"**.
7. Test in the Studio panel:
   - `publish_audit("0x<42 chars>", "87", "SAFE", "No critical issues")`
   - `get_audit("0x<same>")` → should return `87|SAFE|No critical issues`
   - `analyze_and_publish("0x<42 chars>", "Some contract source/context")` → LLM run
   - `has_audit("0x<same>")` → `true`

## Notes

- `publish_audit` is deterministic and does not call an LLM — deploy this one
  first so your first Studio run always succeeds.
- `analyze_and_publish` uses `prompt_non_comparative` so validators judge the
  summary against the provided context instead of requiring identical wording.
- Storage uses only GenLayer types (`TreeMap[str, str]`). No plain `dict`/`list`,
  no `requests`/`openai`/`anthropic`, no Solidity.
