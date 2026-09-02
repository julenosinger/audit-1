# AuditAI — Intelligent Contract (GenLayer)

`contracts/audit_ai.py` is the on-chain companion to the AuditAI frontend.
It stores mutable audit records (`score`, `verdict`, `summary`) for any EVM
contract address and makes them queryable later.

> Records are mutable, caller-submitted analyses. A later `publish_audit`,
> `analyze_and_publish`, or `analyze_evidence` from any caller overwrites the
> stored record for that address. This is not an append-only audit log.

## Methods

| Method | Kind | Description |
| --- | --- | --- |
| `publish_audit(contract_addr, score, verdict, findings)` | write | Deterministic, no LLM. Publishes an off-chain (local-scan) result. Use this for the first deploy. |
| `analyze_and_publish(contract_addr, source_or_context)` | write | GenLayer-native: LLM adjudication via `gl.eq_principle.prompt_non_comparative`. |
| `get_audit(contract_addr)` | view | `"{score}|{verdict}|{summary}"` or `"NO_AUDIT"`. |
| `get_score(contract_addr)` | view | `"0".."100"`. |
| `get_verdict(contract_addr)` | view | `SAFE | WARNING | DANGER`. |
| `get_author(contract_addr)` | view | sender hex that published. |
| `has_audit(contract_addr)` | view | `bool`. |

## Deploy in GenLayer Studio

1. Finish the portal step **"Star the Boilerplate repo"** and click **Verify**.
2. Add GenLayer networks (**Studionet** chainId `61999` RPC `https://studio.genlayer.com/api`,
   **Bradbury** chainId `4221` RPC `https://rpc-bradbury.genlayer.com`) and get
   **Testnet GEN** from <https://testnet-faucet.genlayer.foundation/>.
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
   - `analyze_and_publish("0x<42 chars>", "<context/bytecode recorte>")` → LLM run by validators
   - `has_audit("0x<same>")` → `true`

## analyze_and_publish flow (LLM on-chain)

The frontend's "Adjudicate with GenLayer LLM" button sends the **context** the
local scanner produced (contract address + a truncated bytecode snippet + local
findings) to `analyze_and_publish`. The leader validator runs the LLM
(`prompt_non_comparative`), and the other validators judge the summary against
the provided context and criteria — reaching consensus without requiring identical
wording. The adjudicated `summary` (with `Score:` and `Verdict:`) is stored on-chain
and read back via `get_audit`.

Key docs:
- Intelligent Contracts: <https://docs.genlayer.com/core-concepts/intelligent-contracts>
- Calling LLMs: <https://docs.genlayer.com/developers/intelligent-contracts/features/calling-llms>
- LlmHelloWorld (prompt_non_comparative): <https://docs.genlayer.com/developers/intelligent-contracts/examples/llm-hello-world>
- Networks: <https://docs.genlayer.com/developers/networks>
- Deploy: <https://docs.genlayer.com/developers/intelligent-contracts/deploying>

## Notes

- `publish_audit` is deterministic and does not call an LLM — deploy this one
  first so your first Studio run always succeeds.
- `analyze_and_publish` uses `prompt_non_comparative` so validators judge the
  summary against the provided context instead of requiring identical wording.
- `publish_audit` validates the score is an integer 0–100 and the verdict is one
  of `SAFE` / `WARNING` / `DANGER`.
- Storage uses only GenLayer types (`TreeMap[str, str]`). No plain `dict`/`list`,
  no `requests`/`openai`/`anthropic`, no Solidity.
