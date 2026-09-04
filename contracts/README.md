# AuditAI — Intelligent Contract (GenLayer), v2

`contracts/audit_ai_v2.py` is the append-only on-chain companion to the AuditAI
frontend. Each analysis is a new immutable record identified by an incrementing
`id`. Old ids are never edited or removed: a second analysis of the same target
creates a *new* id instead of overwriting the previous one (`ids_by_addr` only
appends ids, it never replaces one).

The key property of v2 is that a **verified** record is bound to code, chain and
block context that the **validators themselves fetched** — not to evidence the
caller pasted into the call. The caller supplies only pointers (`target`,
`chain_id`, `block_number`); the contract fetches the bytecode and block header,
hashes the code deterministically, and stores `code_hash` / `block_hash` /
`chain_id` / `block_number` from that fetch.

> v1 (`contracts/audit_ai.py`) was a mutable, address-keyed registry where any
> later caller could overwrite a record. v2 removes that: records are keyed by
> id and written once.

## Storage

| Field | Type | Meaning |
| --- | --- | --- |
| `next_id` | `str` | monotonic id counter ("1", "2", …) |
| `records` | `TreeMap[str, str]` | id → record JSON (written once) |
| `ids_by_addr` | `TreeMap[str, str]` | address → "1,4,9" (append-only) |

A record JSON looks like:

```json
{
  "id": "3",
  "target": "0xabc…",
  "chain_id": "1",
  "block_number": "0x13c1f5b",
  "block_hash": "0x…",
  "code_hash": "0x…",
  "author": "0x…",
  "verdict": "SAFE",
  "summary": "…",
  "source": "verified"
}
```

`source` is `"verified"` only for `analyze_verified`; the legacy methods produce
`"caller_supplied"` records (no verified badge).

## Methods

| Method | Kind | Description |
| --- | --- | --- |
| `analyze_verified(target, chain_id, block_number)` | write | The **only** write that produces a verified badge. Validators fetch code + block header, hash the code, optionally run the LLM, write a new id. Returns the id. |
| `publish_audit(contract_addr, score, verdict, findings)` | write | Legacy. Writes a new `caller_supplied` id (never overwrites, never earns a verified badge). |
| `analyze_and_publish(contract_addr, source_or_context)` | write | Legacy. LLM adjudication over caller context → `caller_supplied` id. |
| `analyze_evidence(contract_addr, evidence_json)` | write | Legacy. Structured LLM assessment over caller evidence → `caller_supplied` id. |
| `get_record(id)` | view | Record JSON, or `"NO_RECORD"`. |
| `list_ids(target)` | view | `"1,4,9"` or `""`. |
| `latest_id(target)` | view | Latest id, or `""`. |
| `get_audit(target)` | view | Shortcut to the latest record (or `"NO_AUDIT"`); never mutates ids. |

## How `analyze_verified` fetches code/block (documented RPC)

`analyze_verified(target, chain_id, block_number)` has the validators fetch the
code and block header themselves through the GenLayer web/nondet API
(`gl.nondet.web.request`) and reach consensus with `gl.eq_principle.strict_eq`
(because `eth_getCode` / `eth_getBlockByNumber` at a *fixed* block are
deterministic).

- **EVM chains** — `eth_getCode(target, block)` + `eth_getBlockByNumber(block, false)`
  against the chain's public endpoint.
- **GenLayer (chain_id `4221`)** — `gen_getContractCode({"address": target})`
  (the official SDK method, base64 source) + `eth_getBlockByNumber(block, false)`.

`RPC_BY_CHAIN` (inside the contract) maps the supported `chain_id` values to
their public endpoints:

| chain_id | network | endpoint |
| --- | --- | --- |
| `1` | Ethereum | `https://ethereum-rpc.publicnode.com` |
| `56` | BNB Smart Chain | `https://bsc-rpc.publicnode.com` |
| `8453` | Base | `https://mainnet.base.org` |
| `42161` | Arbitrum One | `https://arb1.arbitrum.io/rpc` |
| `10` | Optimism | `https://mainnet.optimism.io` |
| `61999` | GenLayer Studionet | `https://studio.genlayer.com/api` |
| `4221` | GenLayer Bradbury | `https://rpc-bradbury.genlayer.com` |

`code_hash` is the deterministic `sha256` of the fetched code
(`"0x" + hexdigest`, lowercased for EVM bytecode). If the fetch fails, or the
target has no code, the write raises `RuntimeError` and no record is written.

The optional LLM (`gl.eq_principle.prompt_non_comparative`) receives only a short
excerpt of the *fetched* code plus `chain_id` / `block_number` / `code_hash`.
It never receives the app's evidence JSON.

## Deploy in GenLayer Studio (Bradbury)

1. Finish the portal step **"Star the Boilerplate repo"** and click **Verify**.
2. Add GenLayer networks (**Studionet** chainId `61999` RPC `https://studio.genlayer.com/api`,
   **Bradbury** chainId `4221` RPC `https://rpc-bradbury.genlayer.com`) and get
   **Testnet GEN** from <https://testnet-faucet.genlayer.foundation/>.
3. Open <https://studio.genlayer.com/validators> and create **≥ 1 validator**
   (choose a provider + model, stake ≥ 1 GEN).
4. Open <https://studio.genlayer.com/> → **Contracts** → **Add From File** →
   select `contracts/audit_ai_v2.py`.
5. Open the file → **Run and Debug** → leave the constructor empty → **Deploy**.
6. Copy the deployed **contract address** and paste it into the portal step
   **"Deploy your first contract"**.
7. Test in the Studio panel:
   - `analyze_verified("0x<target>", "1", "0x<block>")` → returns a record id (e.g. `"1"`)
   - `get_record("1")` → JSON with non-empty `code_hash` and `block_hash`
   - `analyze_verified("0x<same target>", "1", "0x<block>")` → returns a *new* id (e.g. `"2"`)
   - `get_record("1")` → still the original record (unchanged)
   - `list_ids("0x<target>")` → `"1,2"`

> Deploy a **new** contract for v2 — do not reuse the v1 Bradbury address
> (`0x119Ac58AF8546Df0B0E55eB24277C756d9458000`).

Key docs:
- Intelligent Contracts: <https://docs.genlayer.com/core-concepts/intelligent-contracts>
- Calling LLMs: <https://docs.genlayer.com/developers/intelligent-contracts/features/calling-llms>
- Web Access (nondet): <https://docs.genlayer.com/developers/intelligent-contracts/features/web-access>
- Equivalence Principle (`strict_eq` / `prompt_non_comparative`): <https://docs.genlayer.com/developers/intelligent-contracts/equivalence-principle>
- Networks: <https://docs.genlayer.com/developers/networks>
- Deploy: <https://docs.genlayer.com/developers/intelligent-contracts/deploying>

## Notes

- Storage uses only GenLayer types (`TreeMap[str, str]` and `str`). No plain
  `dict`/`list` as state, no `requests`/`openai`/`anthropic`, no Solidity.
- `analyze_verified` is the only source of `source: "verified"` records; the
  frontend's verified badge must require a non-empty `code_hash` **and**
  `block_hash` read back via `get_record`.
- A write that cannot fetch the code/block raises `RuntimeError` and never
  writes an empty record.
