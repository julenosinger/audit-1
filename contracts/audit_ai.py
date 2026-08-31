# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
import typing
import re

VALID_VERDICTS = ("SAFE", "WARNING", "DANGER")


class AuditAI(gl.Contract):
    """Immutable on-chain registry for smart-contract security audits.

    Deterministic path: `publish_audit` stores a result that was already
    computed off-chain (e.g. by AuditAI's Claude/ethers frontend). No LLM here,
    so it deploys and runs cleanly in GenLayer Studio on the first try.

    GenLayer-native path: `analyze_and_publish` asks an LLM on-chain via the
    non-comparative Equivalence Principle, then persists the adjudicated text.
    """

    # Storage — only GenLayer storage types (no plain dict/list).
    reports: TreeMap[str, str]     # contract address -> summary text
    scores: TreeMap[str, str]      # contract address -> "0".."100"
    verdicts: TreeMap[str, str]    # contract address -> SAFE | WARNING | DANGER
    authors: TreeMap[str, str]     # contract address -> sender hex

    def __init__(self):
        # TreeMaps are zero-initialized, but explicit construction makes the
        # deploy path unambiguous in Studio.
        self.reports = TreeMap[str, str]()
        self.scores = TreeMap[str, str]()
        self.verdicts = TreeMap[str, str]()
        self.authors = TreeMap[str, str]()

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
        return verdict.strip().upper()

    # ── deterministic write (no LLM) — use from the frontend ────────────────

    @gl.public.write
    def publish_audit(
        self, contract_addr: str, score: str, verdict: str, findings: str
    ) -> None:
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

        self.reports[contract_addr] = findings
        self.scores[contract_addr] = s
        self.verdicts[contract_addr] = v
        self.authors[contract_addr] = self._sender_hex()

    # ── GenLayer-native write (LLM adjudication on-chain) ───────────────────

    @gl.public.write
    def analyze_and_publish(self, contract_addr: str, source_or_context: str) -> None:
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

        self.reports[contract_addr] = summary
        score, verdict = self._parse_summary(summary)
        self.scores[contract_addr] = score
        self.verdicts[contract_addr] = verdict
        self.authors[contract_addr] = self._sender_hex()

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

    # ── views ────────────────────────────────────────────────────────────────

    @gl.public.view
    def get_audit(self, contract_addr: str) -> str:
        if not self.has_audit(contract_addr):
            return "NO_AUDIT"
        return (
            self.scores.get(contract_addr, "0")
            + "|"
            + self.verdicts.get(contract_addr, "WARNING")
            + "|"
            + self.reports.get(contract_addr, "")
        )

    @gl.public.view
    def get_score(self, contract_addr: str) -> str:
        return self.scores.get(contract_addr, "0")

    @gl.public.view
    def get_verdict(self, contract_addr: str) -> str:
        return self.verdicts.get(contract_addr, "WARNING")

    @gl.public.view
    def get_author(self, contract_addr: str) -> str:
        return self.authors.get(contract_addr, "")

    @gl.public.view
    def has_audit(self, contract_addr: str) -> bool:
        return self.reports.get(contract_addr, "") != ""
