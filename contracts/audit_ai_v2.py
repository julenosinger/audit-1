# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
import typing
import re
import json
import hashlib
import base64

VALID_VERDICTS = ("SAFE", "WARNING", "DANGER")

# chain_id -> public JSON-RPC endpoint used by validators to fetch code/block.
# Only these chains are bound; anything else raises before any record is written.
RPC_BY_CHAIN = {
    "1": "https://ethereum-rpc.publicnode.com",
    "56": "https://bsc-rpc.publicnode.com",
    "8453": "https://mainnet.base.org",
    "42161": "https://arb1.arbitrum.io/rpc",
    "10": "https://mainnet.optimism.io",
    "61999": "https://studio.genlayer.com/api",
    "4221": "https://rpc-bradbury.genlayer.com",
}

GENLAYER_CHAIN_ID = "4221"


class AuditAI(gl.Contract):
    """On-chain audit registry (v2) — append-only records bound to code the
    validators themselves fetched.

    Every analysis is a new immutable record identified by an incrementing id.
    Old ids are never edited and never removed. The registry is keyed by id, not
    by address, so a second analysis of the same target creates a *new* id
    instead of overwriting the previous one. `ids_by_addr` only ever appends ids
    to an address's list; it never replaces one.

    `analyze_verified` is the only write that binds a record to independently
    fetched context. The caller supplies only pointers (target, chain_id,
    block_number); the validators fetch the bytecode and block header themselves
    via the documented GenLayer web/nondet API, hash the code deterministically,
    and store the resulting code_hash / block_hash. Caller-supplied evidence is
    therefore never the source of truth for a verified record.

    The legacy methods (`publish_audit`, `analyze_and_publish`,
    `analyze_evidence`) remain for backward compatibility but only produce
    `caller_supplied` records (no verified badge): their content is taken from
    the caller, not from a validator fetch.
    """

    # Storage — only GenLayer storage types (no plain dict/list as state).
    next_id: str                  # "1", "2", … (monotonic id counter)
    records: TreeMap[str, str]    # id -> record JSON (written once, never edited)
    ids_by_addr: TreeMap[str, str]  # "0xabc…" -> "1,4,9" (append-only)

    def __init__(self):
        self.next_id = "1"
        self.records = TreeMap[str, str]()
        self.ids_by_addr = TreeMap[str, str]()

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _valid_address(addr: str) -> bool:
        return bool(addr) and addr.startswith("0x") and len(addr) == 42

    @staticmethod
    def _sender_hex() -> str:
        sender = gl.message.sender_address
        try:
            return sender.as_hex
        except AttributeError:
            return str(sender)

    @staticmethod
    def _normalize_verdict(verdict: str) -> str:
        return (verdict or "").strip().upper()

    @staticmethod
    def _normalize_target(addr: str) -> str:
        return (addr or "").strip().lower()

    def _next_id(self) -> str:
        rid = self.next_id
        self.next_id = str(int(rid) + 1)
        return rid

    @staticmethod
    def _append_id(existing: str, rid: str) -> str:
        existing = (existing or "").strip()
        if not existing:
            return rid
        return existing + "," + rid

    # ── deterministic code hash (code fetched by validators, not the caller) ──

    @staticmethod
    def _hash_code(code: str) -> str:
        s = (code or "").strip()
        if not s:
            return ""
        # EVM bytecode is hex and case-insensitive; GenLayer source is not.
        if s.startswith("0x"):
            s = s.lower()
        return "0x" + hashlib.sha256(s.encode("utf-8")).hexdigest()

    # ── verified context fetch (web/nondet, documented GenLayer API) ─────────
    #
    # Validators POST JSON-RPC to the chain's public endpoint via
    # gl.nondet.web.request and reach consensus with gl.eq_principle.strict_eq
    # because eth_getCode / eth_getBlockByNumber at a *fixed* block are
    # deterministic. The leader's canonical result is accepted only when every
    # validator independently reproduces the same bytes.

    @staticmethod
    def _rpc_post(rpc_url: str, method: str, params: typing.List) -> dict:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}

        def call() -> str:
            resp = gl.nondet.web.request(rpc_url, method="POST", body=payload)
            if resp.status_code >= 400:
                raise RuntimeError("RPC HTTP " + str(resp.status_code))
            data = json.loads(resp.body.decode("utf-8"))
            if data.get("error"):
                raise RuntimeError("RPC error: " + str(data["error"]))
            result = data.get("result")
            if result is None:
                raise RuntimeError("RPC returned no result for " + method)
            return json.dumps(result, sort_keys=True)

        canonical = gl.eq_principle.strict_eq(call)
        return json.loads(canonical)

    @staticmethod
    def _fetch_evm_code(rpc_url: str, target: str, block: str) -> str:
        code = AuditAI._rpc_post(rpc_url, "eth_getCode", [target, block])
        if not isinstance(code, str):
            raise RuntimeError("eth_getCode returned a non-string")
        return code

    @staticmethod
    def _fetch_genlayer_code(rpc_url: str, target: str) -> str:
        # GenLayer Bradbury RPC: gen_getContractCode expects [{ "address": target }]
        # and returns the contract source as base64 (mirrors the official SDK).
        raw = AuditAI._rpc_post(rpc_url, "gen_getContractCode", [{"address": target}])
        if not isinstance(raw, str):
            raise RuntimeError("gen_getContractCode returned a non-string")
        try:
            return base64.b64decode(raw).decode("utf-8")
        except Exception:
            raise RuntimeError("could not decode gen_getContractCode result")

    @staticmethod
    def _fetch_block_hash(rpc_url: str, block: str) -> str:
        header = AuditAI._rpc_post(rpc_url, "eth_getBlockByNumber", [block, False])
        if not isinstance(header, dict) or not header.get("hash"):
            raise RuntimeError("block header not found for block " + str(block))
        return str(header["hash"]).lower()

    def _fetch_context(self, target: str, chain_id: str, block_number: str):
        rpc = RPC_BY_CHAIN.get(str(chain_id), "")
        if not rpc:
            raise RuntimeError("unsupported chain_id: " + str(chain_id))
        block = str(block_number).strip() or "latest"
        if str(chain_id) == GENLAYER_CHAIN_ID:
            code = self._fetch_genlayer_code(rpc, target)
        else:
            code = self._fetch_evm_code(rpc, target, block)
        if not code or code in ("0x", "0x0"):
            raise RuntimeError("no code at target on chain " + str(chain_id))
        block_hash = self._fetch_block_hash(rpc, block)
        code_hash = self._hash_code(code)
        return code, code_hash, block_hash

    # ── optional LLM assessment (never sees the app's evidence JSON) ─────────
    # The LLM only receives a short excerpt of the *fetched* code plus the
    # chain/block/hash. It is optional: if it fails the record is still written
    # with the code/block binding (verdict/summary are left empty).

    def _llm_assessment(
        self, code: str, chain_id: str, block_number: str, code_hash: str
    ) -> typing.Tuple[str, str]:
        snippet = (code or "")[:4000]
        context = (
            "chain_id=" + str(chain_id)
            + " block_number=" + str(block_number)
            + " code_hash=" + str(code_hash)
            + "\n--- code excerpt ---\n" + snippet
        )

        def get_input() -> str:
            return context

        try:
            summary = gl.eq_principle.prompt_non_comparative(
                get_input,
                task=(
                    "Act as a smart-contract security auditor. Based ONLY on the "
                    "provided code excerpt and chain/block context, write a short "
                    "audit summary (max 600 chars) that ends with a line "
                    "'Score: <0-100>' and a line 'Verdict: <SAFE|WARNING|DANGER>'."
                ),
                criteria="""
                    The summary is grounded in the provided code excerpt and does
                    not invent exploits that have no basis in that excerpt.
                    It contains a numeric score between 0 and 100.
                    It contains a verdict of exactly SAFE, WARNING, or DANGER.
                    It is at most 600 characters.
                """,
            )
            _, verdict = self._parse_summary(summary)
            return verdict, summary
        except Exception:
            return "", ""

    @staticmethod
    def _parse_summary(text: str) -> typing.Tuple[str, str]:
        score = "0"
        m = re.search(r"score\s*[:=]\s*(\d{1,3})", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\b(\d{1,3})\b", text)
        if m:
            try:
                n = int(m.group(1))
                score = str(max(0, min(100, n)))
            except ValueError:
                score = "0"

        verdict = "WARNING"
        upper = text.upper()
        for v in ("DANGER", "WARNING", "SAFE"):
            if v in upper:
                verdict = v
                break

        return score, verdict

    # ── record creation (id-keyed, append-only) ──────────────────────────────

    def _store_record(
        self,
        target: str,
        chain_id: str,
        block_number: str,
        block_hash: str,
        code_hash: str,
        verdict: str,
        summary: str,
        source: str,
    ) -> str:
        rid = self._next_id()
        record = {
            "id": rid,
            "target": target,
            "chain_id": str(chain_id),
            "block_number": str(block_number),
            "block_hash": block_hash or "",
            "code_hash": code_hash or "",
            "author": self._sender_hex(),
            "verdict": verdict or "",
            "summary": summary or "",
            "source": source,
        }
        self.records[rid] = json.dumps(record, sort_keys=True)
        existing = self.ids_by_addr.get(target, "")
        self.ids_by_addr[target] = self._append_id(existing, rid)
        return rid

    # ── verified write (the only path that binds to fetched code/block) ──────

    @gl.public.write
    def analyze_verified(self, target: str, chain_id: str, block_number: str) -> str:
        if not self._valid_address(target):
            raise RuntimeError("target must start with 0x and be 42 chars")

        normalized = self._normalize_target(target)

        # Validators fetch code + block header themselves (never the caller's).
        code, code_hash, block_hash = self._fetch_context(
            normalized, chain_id, block_number
        )
        if not code_hash:
            raise RuntimeError("could not hash fetched code")

        verdict, summary = self._llm_assessment(
            code, chain_id, block_number, code_hash
        )

        return self._store_record(
            target=normalized,
            chain_id=chain_id,
            block_number=block_number,
            block_hash=block_hash,
            code_hash=code_hash,
            verdict=verdict,
            summary=summary,
            source="verified",
        )

    # ── legacy writes (caller_supplied — never earn the verified badge) ──────

    @gl.public.write
    def publish_audit(
        self, contract_addr: str, score: str, verdict: str, findings: str
    ) -> str:
        if not self._valid_address(contract_addr):
            raise RuntimeError("contract_addr must start with 0x and be 42 chars")

        v = self._normalize_verdict(verdict)
        if v not in VALID_VERDICTS:
            raise RuntimeError("verdict must be one of SAFE, WARNING, DANGER")

        s = str(score).strip()
        try:
            n = int(s)
            if n < 0 or n > 100:
                raise RuntimeError("score must be an integer between 0 and 100")
        except ValueError:
            raise RuntimeError("score must be an integer between 0 and 100")

        target = self._normalize_target(contract_addr)
        return self._store_record(
            target=target,
            chain_id="",
            block_number="",
            block_hash="",
            code_hash="",
            verdict=v,
            summary="score=" + s + " | " + findings,
            source="caller_supplied",
        )

    @gl.public.write
    def analyze_and_publish(self, contract_addr: str, source_or_context: str) -> str:
        if not self._valid_address(contract_addr):
            raise RuntimeError("contract_addr must start with 0x and be 42 chars")

        def get_input() -> str:
            return source_or_context

        summary: str = gl.eq_principle.prompt_non_comparative(
            get_input,
            task=(
                "Act as a smart-contract security auditor. Based ONLY on the "
                "provided context, write a short audit summary (max 600 chars) "
                "that ends with a line 'Score: <0-100>' and a line "
                "'Verdict: <SAFE|WARNING|DANGER>'."
            ),
            criteria="""
                The summary is grounded in the provided context and does not
                invent exploits that have no basis in that context.
                It contains a numeric score between 0 and 100.
                It contains a verdict of exactly SAFE, WARNING, or DANGER.
                It is at most 600 characters.
            """,
        )

        _, verdict = self._parse_summary(summary)
        target = self._normalize_target(contract_addr)
        return self._store_record(
            target=target,
            chain_id="",
            block_number="",
            block_hash="",
            code_hash="",
            verdict=verdict,
            summary=summary,
            source="caller_supplied",
        )

    @gl.public.write
    def analyze_evidence(self, contract_addr: str, evidence_json: str) -> str:
        if not self._valid_address(contract_addr):
            raise RuntimeError("contract_addr must start with 0x and be 42 chars")

        def get_input() -> str:
            return evidence_json

        result: str = gl.eq_principle.prompt_non_comparative(
            get_input,
            task=(
                "You are a smart-contract security analysis verifier. Based ONLY "
                "on the supplied evidence JSON, produce a structured assessment "
                "with: verdict (one of NO_CONFIRMED_VULNERABILITY, "
                "POTENTIAL_VULNERABILITY, LIKELY_VULNERABILITY, "
                "CONFIRMED_VULNERABILITY, NEEDS_REVIEW), confidence "
                "(HIGH/MEDIUM/LOW), and a findings array where each finding has "
                "id, category, severity, confidence, verdict, reasoning, "
                "evidenceRefs (only ids present in the evidence), "
                "contradictions, and recommendation."
            ),
            criteria="""
                The response is a valid JSON object with verdict, confidence, and findings.
                Every evidence reference points to an evidence id present in the supplied evidence.
                The response does not invent facts, function names, storage slots, permissions, addresses, fees, selectors, or vulnerabilities.
                The response distinguishes OBSERVED, INFERRED, and UNKNOWN.
                The response is conservative and never confirms a vulnerability without explicit support in the evidence.
            """,
        )

        target = self._normalize_target(contract_addr)
        return self._store_record(
            target=target,
            chain_id="",
            block_number="",
            block_hash="",
            code_hash="",
            verdict="",
            summary=result,
            source="caller_supplied",
        )

    # ── views ────────────────────────────────────────────────────────────────

    @gl.public.view
    def get_record(self, record_id: str) -> str:
        rec = self.records.get(record_id, "")
        if not rec:
            return "NO_RECORD"
        return rec

    @gl.public.view
    def list_ids(self, target: str) -> str:
        return self.ids_by_addr.get(self._normalize_target(target), "")

    @gl.public.view
    def latest_id(self, target: str) -> str:
        ids = self.ids_by_addr.get(self._normalize_target(target), "")
        if not ids:
            return ""
        return ids.split(",")[-1]

    @gl.public.view
    def get_audit(self, target: str) -> str:
        # Shortcut to the latest record (does not remove or mutate ids).
        latest = self.latest_id(target)
        if not latest:
            return "NO_AUDIT"
        return self.get_record(latest)
