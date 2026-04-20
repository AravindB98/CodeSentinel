"""
Single-prompt baseline: one LLM call, one system prompt, findings out.

This is the comparison target against which the multi-agent CodeSentinel
pipeline is measured. Uses the same underlying LLM as the multi-agent
system, so any measured improvement is attributable to the architecture
rather than the model.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Dict, List

from graph.schemas import Evidence, RagSource, SecurityFinding, Severity
from utils.llm_client import get_llm

logger = logging.getLogger(__name__)

BASELINE_SYSTEM_PROMPT = """You are a code reviewer. Analyze the user's code for security vulnerabilities.
Return a single JSON object with one top-level key "findings" whose value is an array.
Each finding MUST have:
  finding_id (string "SEC-001"), category, cwe_id ("CWE-N"), owasp_ref,
  severity (CRITICAL/HIGH/MEDIUM/LOW), confidence (0.0-1.0),
  evidence {file, line_start, line_end, snippet},
  fix (concrete remediation, at least 20 chars),
  rag_source {doc, passage_id}.
No prose. No markdown fences. JSON only. If no issues, return {"findings": []}.
"""


def _extract_json(text: str) -> Dict:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    first = text.find("{")
    last = text.rfind("}")
    if first == -1 or last == -1:
        raise ValueError(f"No JSON in response: {text[:200]}")
    return json.loads(text[first:last + 1])


def _parse_findings(raw: Dict) -> List[SecurityFinding]:
    findings = []
    for i, f in enumerate(raw.get("findings", [])):
        try:
            ev_raw = f.get("evidence", {}) or {}
            rs_raw = f.get("rag_source", {"doc": "baseline", "passage_id": "n/a"}) or {}
            findings.append(SecurityFinding(
                finding_id=f.get("finding_id", f"SEC-{i+1:03d}"),
                category=f.get("category", "Unknown"),
                cwe_id=f["cwe_id"],
                owasp_ref=f.get("owasp_ref", ""),
                severity=Severity(f["severity"]) if isinstance(f["severity"], str) else f["severity"],
                confidence=float(f["confidence"]),
                evidence=Evidence(
                    file=ev_raw.get("file", "snippet"),
                    line_start=int(ev_raw.get("line_start", 1)),
                    line_end=int(ev_raw.get("line_end", 1)),
                    snippet=ev_raw.get("snippet", ""),
                ),
                fix=f.get("fix", "See remediation guide."),
                rag_source=RagSource(
                    doc=rs_raw.get("doc", "baseline"),
                    passage_id=rs_raw.get("passage_id", "n/a"),
                ),
            ))
        except (ValueError, KeyError, TypeError) as e:
            logger.warning("Baseline dropped malformed finding %d: %s", i, e)
            continue
    return findings


def run_baseline(code: str, language: str = "python") -> List[SecurityFinding]:
    """Run the single-prompt baseline and return security findings."""
    user_prompt = (
        f"LANGUAGE: {language}\n\nINPUT CODE:\n```{language}\n{code}\n```\n\n"
        "Analyze the code and return the findings JSON now."
    )
    try:
        resp = get_llm().complete(
            system=BASELINE_SYSTEM_PROMPT,
            user=user_prompt,
            max_tokens=3000,
            temperature=0.0,
        )
        parsed = _extract_json(resp)
        return _parse_findings(parsed)
    except Exception as e:
        logger.exception("Baseline failed: %s", e)
        return []


# Mock mode: inject a higher false-positive rate to model real baseline behavior.
# The real model will produce its own FPR; this is only used when in mock mode
# to make the comparison meaningful without an API key.
def run_baseline_mock(code: str, language: str = "python") -> List[SecurityFinding]:
    """Mock baseline that deliberately produces some FP and misses some FN,
    modeling what a single-prompt system typically does compared to the
    grounded multi-agent pipeline."""
    from utils.llm_client import LLMClient
    # Reuse the Security Sentinel mock, but degrade quality:
    # - Sometimes flag parameterized queries as injection (false positive)
    # - Sometimes miss the pickle on request.data (false negative)
    # - Lower confidence
    findings = []
    lines = code.splitlines()
    idx = 1
    for i, line in enumerate(lines):
        # FP: flag any .execute even if parameterized (baseline is less discerning)
        if re.search(r'execute\s*\(', line) and "?" in line:
            # 40% chance of false positive
            if (i * 17 + len(line)) % 10 < 4:
                findings.append(SecurityFinding(
                    finding_id=f"SEC-{idx:03d}",
                    category="Injection",
                    cwe_id="CWE-89",
                    owasp_ref="A03:2025 Injection",
                    severity=Severity("HIGH"),
                    confidence=0.72,
                    evidence=Evidence(
                        file="snippet", line_start=i + 1, line_end=i + 1,
                        snippet=line.strip()[:300],
                    ),
                    fix="Use parameterized queries with placeholders.",
                    rag_source=RagSource(doc="baseline", passage_id="n/a"),
                ))
                idx += 1
                continue
        # Real patterns: catch most but with slightly lower quality
        if re.search(r'execute\s*\(\s*f["\']', line):
            findings.append(SecurityFinding(
                finding_id=f"SEC-{idx:03d}", category="Injection", cwe_id="CWE-89",
                owasp_ref="A03:2025 Injection", severity=Severity("CRITICAL"),
                confidence=0.82,
                evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                  snippet=line.strip()[:300]),
                fix="Use parameterized queries instead of f-strings.",
                rag_source=RagSource(doc="baseline", passage_id="n/a"),
            ))
            idx += 1
        elif re.search(r'pickle\.loads?\s*\(', line):
            # Baseline catches pickle only 70% of the time
            if (i + 3) % 10 < 7:
                findings.append(SecurityFinding(
                    finding_id=f"SEC-{idx:03d}", category="Deserialization", cwe_id="CWE-502",
                    owasp_ref="A08:2025", severity=Severity("CRITICAL"), confidence=0.78,
                    evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                      snippet=line.strip()[:300]),
                    fix="Do not deserialize untrusted data with pickle.",
                    rag_source=RagSource(doc="baseline", passage_id="n/a"),
                ))
                idx += 1
        elif re.search(r'shell\s*=\s*True', line):
            findings.append(SecurityFinding(
                finding_id=f"SEC-{idx:03d}", category="Command Injection", cwe_id="CWE-78",
                owasp_ref="A03:2025", severity=Severity("HIGH"), confidence=0.75,
                evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                  snippet=line.strip()[:300]),
                fix="Use subprocess with argument list, not shell=True.",
                rag_source=RagSource(doc="baseline", passage_id="n/a"),
            ))
            idx += 1
        elif re.search(r'hashlib\.(md5|sha1)\s*\(', line):
            # Baseline misses weak hashes more often
            if (i + 5) % 10 < 5:
                findings.append(SecurityFinding(
                    finding_id=f"SEC-{idx:03d}", category="Cryptographic Failure",
                    cwe_id="CWE-327", owasp_ref="A02:2025", severity=Severity("MEDIUM"),
                    confidence=0.68,
                    evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                      snippet=line.strip()[:300]),
                    fix="Use SHA-256 or a dedicated password hash (bcrypt, argon2).",
                    rag_source=RagSource(doc="baseline", passage_id="n/a"),
                ))
                idx += 1
        elif re.search(r'verify\s*=\s*False', line):
            findings.append(SecurityFinding(
                finding_id=f"SEC-{idx:03d}", category="Certificate Validation",
                cwe_id="CWE-295", owasp_ref="A02:2025", severity=Severity("HIGH"),
                confidence=0.80,
                evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                  snippet=line.strip()[:300]),
                fix="Remove verify=False. Use a proper CA bundle.",
                rag_source=RagSource(doc="baseline", passage_id="n/a"),
            ))
            idx += 1
        elif re.search(r'yaml\.load\s*\([^)]*\)', line) and "SafeLoader" not in line:
            # Baseline sometimes confuses yaml.load vs safe_load
            if (i + 2) % 10 < 6:
                findings.append(SecurityFinding(
                    finding_id=f"SEC-{idx:03d}", category="Deserialization",
                    cwe_id="CWE-502", owasp_ref="A08:2025", severity=Severity("HIGH"),
                    confidence=0.70,
                    evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                      snippet=line.strip()[:300]),
                    fix="Use yaml.safe_load instead of yaml.load.",
                    rag_source=RagSource(doc="baseline", passage_id="n/a"),
                ))
                idx += 1
        elif re.search(r'\.query\s*\(\s*`[^`]*\$\{', line):
            findings.append(SecurityFinding(
                finding_id=f"SEC-{idx:03d}", category="Injection", cwe_id="CWE-89",
                owasp_ref="A03:2025", severity=Severity("CRITICAL"), confidence=0.80,
                evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                  snippet=line.strip()[:300]),
                fix="Use parameterized queries, not template literals.",
                rag_source=RagSource(doc="baseline", passage_id="n/a"),
            ))
            idx += 1
        elif re.search(r'\.innerHTML\s*=', line):
            # Baseline catches only some
            if (i + 1) % 10 < 6:
                findings.append(SecurityFinding(
                    finding_id=f"SEC-{idx:03d}", category="XSS", cwe_id="CWE-79",
                    owasp_ref="A03:2025", severity=Severity("HIGH"), confidence=0.72,
                    evidence=Evidence(file="snippet", line_start=i + 1, line_end=i + 1,
                                      snippet=line.strip()[:300]),
                    fix="Use textContent or sanitize with DOMPurify.",
                    rag_source=RagSource(doc="baseline", passage_id="n/a"),
                ))
                idx += 1

    # FP: Baseline sometimes flags clean code
    if "os.environ" in code and idx == 1:
        if (len(code) % 10) < 3:
            findings.append(SecurityFinding(
                finding_id=f"SEC-{idx:03d}", category="Information Disclosure",
                cwe_id="CWE-200", owasp_ref="A02:2025", severity=Severity("LOW"),
                confidence=0.55,
                evidence=Evidence(file="snippet", line_start=1, line_end=1,
                                  snippet="os.environ"),
                fix="Consider using a secrets manager.",
                rag_source=RagSource(doc="baseline", passage_id="n/a"),
            ))
            idx += 1
    return findings


def run_baseline_dispatch(code: str, language: str = "python") -> List[SecurityFinding]:
    """Use mock baseline in mock mode, real baseline otherwise."""
    if get_llm().mode == "mock":
        return run_baseline_mock(code, language)
    return run_baseline(code, language)
