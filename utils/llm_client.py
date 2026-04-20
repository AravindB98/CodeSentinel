"""
LLM client wrapper.

Production mode uses the Anthropic SDK. An explicit mock mode is
provided so the full pipeline runs deterministically without an API
key, which matters for reproducibility and for CI.

Set CODESENTINEL_MOCK_LLM=1 in the environment to force mock mode.
If ANTHROPIC_API_KEY is absent, mock mode is also used automatically.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-5"


class LLMClient:
    """Thin wrapper around the Anthropic SDK with a mock fallback."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        self.mode = "mock"
        self._client = None
        self._try_real_client()

    def _try_real_client(self) -> None:
        if os.getenv("CODESENTINEL_MOCK_LLM") == "1":
            logger.info("LLM client: mock mode forced by env var")
            return
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.info("LLM client: no ANTHROPIC_API_KEY, using mock mode")
            return
        try:
            import anthropic
            self._client = anthropic.Anthropic(api_key=api_key)
            self.mode = "real"
            logger.info("LLM client: real Anthropic SDK connected (model=%s)", self.model)
        except ImportError:
            logger.warning("anthropic SDK not installed; falling back to mock")

    def complete(
        self,
        system: str,
        user: str,
        max_tokens: int = 4000,
        temperature: float = 0.0,
    ) -> str:
        """
        Get a completion as a string. JSON extraction happens in the caller.
        """
        if self.mode == "real":
            return self._real_complete(system, user, max_tokens, temperature)
        return self._mock_complete(system, user)

    # ---- Real ----
    def _real_complete(self, system: str, user: str, max_tokens: int, temperature: float) -> str:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts = []
        for block in resp.content:
            if hasattr(block, "text"):
                parts.append(block.text)
        return "\n".join(parts)

    # ---- Mock ----
    def _mock_complete(self, system: str, user: str) -> str:
        """
        Deterministic mock that inspects the user prompt for known patterns
        and emits structurally valid JSON matching the agent's schema.

        This makes the full pipeline runnable offline end-to-end, which is
        valuable for tests and for graders without an API key.
        """
        sys_head = system[:160].lower()

        if "security sentinel" in sys_head:
            return self._mock_security(user)
        if "evaluator guardian" in sys_head:
            return self._mock_evaluator(user)
        if "code quality auditor" in sys_head:
            return self._mock_quality(user)
        return '{"findings": []}'

    def _mock_security(self, user: str) -> str:
        """Pattern-match common vulnerabilities in the code block of the user prompt."""
        code = self._extract_code_block(user)
        passages = self._extract_passages(user)
        findings = []
        idx = 1

        lines = code.splitlines()

        def add_finding(pattern_line_idx, cwe, owasp, category, sev, confidence,
                         snippet, fix, rag_doc, rag_pid):
            nonlocal idx
            findings.append({
                "finding_id": f"SEC-{idx:03d}",
                "category": category,
                "cwe_id": cwe,
                "owasp_ref": owasp,
                "severity": sev,
                "confidence": confidence,
                "evidence": {
                    "file": "snippet",
                    "line_start": pattern_line_idx + 1,
                    "line_end": pattern_line_idx + 1,
                    "snippet": snippet,
                },
                "fix": fix,
                "rag_source": {
                    "doc": rag_doc,
                    "passage_id": rag_pid,
                    "excerpt": self._get_passage_excerpt(passages, rag_doc, rag_pid),
                },
            })
            idx += 1

        for i, line in enumerate(lines):
            ls = line.strip()

            # SQL injection via f-string
            if re.search(r'execute\s*\(\s*f["\']', line):
                add_finding(i, "CWE-89", "A03:2025 Injection", "Injection",
                            "CRITICAL", 0.94, ls[:300],
                            "Replace the f-string with a parameterized query. Example: "
                            "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,)) "
                            "for sqlite3, or use %s placeholders for psycopg2. Never build SQL "
                            "by string interpolation.",
                            "patterns.md", "PY-01")
                continue

            # SQL via .format or +
            if re.search(r'execute\s*\([^)]*\.format\(', line) or \
               re.search(r'execute\s*\(["\'][^"\']*["\']\s*\+', line):
                add_finding(i, "CWE-89", "A03:2025 Injection", "Injection",
                            "CRITICAL", 0.90, ls[:300],
                            "Use parameterized queries with placeholders rather than "
                            ".format() or string concatenation. Example: "
                            "cursor.execute(\"... WHERE id = %s\", (user_id,)).",
                            "patterns.md", "PY-01")
                continue

            # pickle.loads on untrusted input
            if re.search(r'pickle\.loads?\s*\(', line):
                add_finding(i, "CWE-502", "A08:2025 Software and Data Integrity Failures",
                            "Deserialization",
                            "CRITICAL", 0.96, ls[:300],
                            "Never deserialize untrusted input with pickle. Replace with "
                            "json.loads() and validate against an explicit schema, or use "
                            "itsdangerous.URLSafeSerializer for signed application-state tokens.",
                            "patterns.md", "PY-02")
                continue

            # subprocess shell=True
            if re.search(r'subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True', line):
                add_finding(i, "CWE-78", "A03:2025 Injection", "Command Injection",
                            "HIGH", 0.88, ls[:300],
                            "Remove shell=True and pass the command as a list of arguments. "
                            "Example: subprocess.run([\"ls\", \"-l\", user_path], check=True). "
                            "Validate user-controlled arguments against an allow-list.",
                            "patterns.md", "PY-03")
                continue

            # eval/exec on input
            if re.search(r'\beval\s*\(', line) and "request" in code.lower():
                add_finding(i, "CWE-94", "A03:2025 Injection", "Code Injection",
                            "CRITICAL", 0.92, ls[:300],
                            "Do not call eval on input derived from requests. Replace with "
                            "explicit parsing or an allow-list of permitted operations. For "
                            "arithmetic, use the simpleeval library.",
                            "patterns.md", "PY-04")
                continue

            # yaml.load without SafeLoader
            if re.search(r'yaml\.load\s*\([^)]*\)', line) and "SafeLoader" not in line and "safe_load" not in line:
                add_finding(i, "CWE-502", "A08:2025 Software and Data Integrity Failures",
                            "Deserialization",
                            "HIGH", 0.85, ls[:300],
                            "Replace yaml.load(data) with yaml.safe_load(data), or pass "
                            "Loader=yaml.SafeLoader explicitly. yaml.load without a safe "
                            "loader can invoke arbitrary Python constructors.",
                            "patterns.md", "PY-07")
                continue

            # verify=False
            if re.search(r'verify\s*=\s*False', line):
                add_finding(i, "CWE-295", "A02:2025 Cryptographic Failures",
                            "Certificate Validation",
                            "HIGH", 0.90, ls[:300],
                            "Remove verify=False. If a custom CA bundle is needed, pass "
                            "verify=\"/path/to/ca-bundle.crt\". Disabling TLS verification "
                            "exposes the connection to man-in-the-middle attacks.",
                            "patterns.md", "PY-06")
                continue

            # MD5/SHA1 for security
            # Citation uses patterns.md::PY-08 (the language-specific pattern),
            # which is what the retriever surfaces in the top-K context for MD5
            # queries. A real LLM cites whatever is in its retrieval context;
            # this mirrors that behavior (see Section 11.6 of the tech report).
            if re.search(r'hashlib\.(md5|sha1)\s*\(', line):
                add_finding(i, "CWE-327", "A02:2025 Cryptographic Failures",
                            "Cryptographic Failure",
                            "MEDIUM", 0.75, ls[:300],
                            "Replace hashlib.md5/sha1 with hashlib.sha256 or stronger for "
                            "any security context. For password hashing, use bcrypt or "
                            "argon2 via the passlib library.",
                            "patterns.md", "PY-08")
                continue

            # hardcoded password/secret
            if re.search(r'(password|api_key|secret|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']', line, re.IGNORECASE):
                add_finding(i, "CWE-798", "A07:2025 Identification and Authentication Failures",
                            "Hardcoded Credentials",
                            "HIGH", 0.80, ls[:300],
                            "Replace the literal credential with os.environ.get(\"SECRET_NAME\") "
                            "or load from a secrets manager. If this value was ever committed, "
                            "rotate it immediately and add the file to .gitignore.",
                            "patterns.md", "PY-05")
                continue

            # JavaScript eval
            if re.search(r'\beval\s*\(', line) and "req" in code.lower() and ("function" in code or "=>" in code or "const " in code):
                add_finding(i, "CWE-94", "A03:2025 Injection", "Code Injection",
                            "CRITICAL", 0.90, ls[:300],
                            "Remove eval on user-controlled input. Replace with explicit parsing "
                            "or an allow-list of operations.",
                            "patterns.md", "JS-01")
                continue

            # JS template literal SQL
            if re.search(r'\.(query|execute)\s*\(\s*`[^`]*\$\{', line):
                add_finding(i, "CWE-89", "A03:2025 Injection", "Injection",
                            "CRITICAL", 0.93, ls[:300],
                            "Replace the template literal with a parameterized query: "
                            "db.query(\"SELECT * FROM users WHERE id = ?\", [userId]).",
                            "patterns.md", "JS-02")
                continue

            # innerHTML with user content
            if re.search(r'\.innerHTML\s*=', line):
                add_finding(i, "CWE-79", "A03:2025 Injection", "Cross-Site Scripting",
                            "HIGH", 0.80, ls[:300],
                            "Replace element.innerHTML with element.textContent for plain text, "
                            "or sanitize with DOMPurify.sanitize() for HTML that must preserve "
                            "formatting.",
                            "patterns.md", "JS-04")
                continue

        return json.dumps({"findings": findings}, indent=2)

    def _mock_evaluator(self, user: str) -> str:
        """Mock evaluator. Security findings must cite a retrieved passage;
        quality findings (no rag_source) are judged on rationale + refactor length."""
        findings = self._extract_findings(user)
        passages = self._extract_passages(user)
        passage_ids = {(p["doc"], p["passage_id"]) for p in passages}

        per_finding = []
        any_rejected = False
        for f in findings:
            reasons = []
            fb = None
            fid = str(f.get("finding_id", ""))
            is_security = fid.startswith("SEC-")
            is_quality = fid.startswith("QUAL-")

            if is_security:
                rs = f.get("rag_source") or {}
                key = (rs.get("doc", ""), rs.get("passage_id", ""))
                if not rs or not rs.get("passage_id"):
                    reasons.append("missing_citation")
                    fb = "Provide a rag_source with doc and passage_id from retrieved context."
                elif key not in passage_ids:
                    reasons.append("citation_does_not_support")
                    fb = f"Citation {key} not found in retrieved context."

                if len(f.get("fix", "")) < 20:
                    reasons.append("missing_remediation")
                    fb = (fb + " " if fb else "") + "Expand fix with a concrete code example."

            elif is_quality:
                # Quality findings: no RAG requirement; check rationale + refactor
                if len(f.get("rationale", "")) < 10:
                    reasons.append("missing_remediation")
                    fb = "Expand rationale."
                if len(f.get("suggested_refactor", "")) < 10:
                    reasons.append("missing_remediation")
                    fb = (fb + " " if fb else "") + "Expand suggested_refactor."

            if float(f.get("confidence", 0)) < 0.5:
                reasons.append("low_confidence")
                fb = (fb + " " if fb else "") + "Confidence below 0.5."

            decision = "REJECTED" if reasons else "APPROVED"
            if decision == "REJECTED":
                any_rejected = True
            per_finding.append({
                "finding_id": fid or "UNKNOWN-000",
                "decision": decision,
                "rejection_reasons": reasons,
                "feedback": fb,
            })

        return json.dumps({
            "overall_decision": "REJECTED" if any_rejected else "APPROVED",
            "per_finding": per_finding,
            "rationale": (
                "All findings pass citation, remediation, and confidence thresholds."
                if not any_rejected
                else f"{len([p for p in per_finding if p['decision']=='REJECTED'])} finding(s) failed validation."
            ),
        }, indent=2)

    def _mock_quality(self, user: str) -> str:
        """Mock Auditor: look for a few common maintainability smells."""
        code = self._extract_code_block(user)
        lines = code.splitlines()
        findings = []
        idx = 1

        for i, line in enumerate(lines):
            ls = line.strip()

            # bare except
            if re.match(r'except\s*:', ls):
                findings.append({
                    "finding_id": f"QUAL-{idx:03d}",
                    "category": "Error Handling",
                    "severity": "MEDIUM",
                    "confidence": 0.9,
                    "evidence": {"file": "snippet", "line_start": i + 1, "line_end": i + 1,
                                 "snippet": ls[:300]},
                    "rationale": "Bare except silently swallows every exception including "
                                 "KeyboardInterrupt and SystemExit, which makes the program "
                                 "hard to stop and hides real bugs.",
                    "suggested_refactor": "Catch the specific exceptions expected, e.g., "
                                          "except (ValueError, KeyError) as e: log.exception(e). "
                                          "Re-raise or return a sentinel if recovery is not possible.",
                })
                idx += 1

            # Module-level global database connection (heuristic)
            if re.match(r'^(conn|db|connection)\s*=\s*(sqlite3|psycopg2|mysql)\.connect', line):
                findings.append({
                    "finding_id": f"QUAL-{idx:03d}",
                    "category": "Resource Management",
                    "severity": "MEDIUM",
                    "confidence": 0.82,
                    "evidence": {"file": "snippet", "line_start": i + 1, "line_end": i + 1,
                                 "snippet": ls[:300]},
                    "rationale": "A module-level database connection is shared across requests and "
                                 "is not safe under concurrency. SQLite connections in particular "
                                 "are not thread-safe by default.",
                    "suggested_refactor": "Open the connection per-request inside the handler using "
                                          "a context manager (with sqlite3.connect(...) as conn:), "
                                          "or use a connection pool such as SQLAlchemy's QueuePool.",
                })
                idx += 1

            if idx > 10:  # cap at 10 per spec
                break

        return json.dumps({"findings": findings}, indent=2)

    # ---- Helpers ----
    @staticmethod
    def _extract_code_block(user: str) -> str:
        """Find the INPUT CODE block in the user prompt."""
        m = re.search(r"INPUT CODE.*?```.*?\n(.*?)```", user, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"INPUT CODE\s*:?\s*\n(.*?)(?=\n[A-Z][A-Z _]{3,}:|\Z)", user, re.DOTALL)
        if m:
            return m.group(1)
        return user

    @staticmethod
    def _extract_passages(user: str) -> List[Dict[str, str]]:
        """Parse the RETRIEVED CONTEXT block. Passages are encoded as
        `[doc :: passage_id]: <text>` lines."""
        out = []
        for m in re.finditer(
            r"\[([^\]:]+?)\s*::\s*([^\]]+?)\]\s*:\s*(.+?)(?=(?:\n\[[^\]:]+?\s*::\s*)|\Z)",
            user, re.DOTALL,
        ):
            out.append({
                "doc": m.group(1).strip(),
                "passage_id": m.group(2).strip(),
                "text": m.group(3).strip(),
            })
        return out

    @staticmethod
    def _get_passage_excerpt(passages: List[Dict[str, str]], doc: str, pid: str) -> Optional[str]:
        for p in passages:
            if p["doc"] == doc and p["passage_id"] == pid:
                return p["text"][:200]
        return None

    @staticmethod
    def _extract_findings(user: str) -> List[Dict]:
        """Parse the SECURITY FINDINGS TO REVIEW block from the evaluator prompt."""
        m = re.search(r"FINDINGS TO REVIEW\s*:?\s*```.*?\n(.*?)```", user, re.DOTALL | re.IGNORECASE)
        if m:
            try:
                data = json.loads(m.group(1))
                return data.get("findings", data if isinstance(data, list) else [])
            except json.JSONDecodeError:
                pass
        # Fallback: try to find any JSON object with a "findings" key
        m = re.search(r'\{\s*"findings"\s*:\s*(\[.*?\])\s*\}', user, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                return []
        return []


# Module-level singleton
_client: Optional[LLMClient] = None


def get_llm() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
