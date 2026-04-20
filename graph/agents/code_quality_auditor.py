"""
Code Quality Auditor agent.

Reviews style, maintainability, and error handling. Intentionally avoids
security territory (that is the Security Sentinel's mandate). Caps at
10 findings per file.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List

from graph.schemas import Evidence, QualityFinding, Severity
from graph.state import CodeSentinelState
from utils.llm_client import get_llm

logger = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "quality.md"


def _load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _build_user_prompt(code: str, language: str, prior_feedback: str = "") -> str:
    parts = [
        f"LANGUAGE: {language}",
        "",
        "INPUT CODE:",
        "```" + (language if language != "unknown" else ""),
        code,
        "```",
    ]
    if prior_feedback:
        parts.extend(["", "PRIOR EVALUATOR FEEDBACK:", prior_feedback])
    parts.extend(["", "Return the findings JSON now."])
    return "\n".join(parts)


def _extract_json(text: str) -> Dict:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    first = text.find("{")
    last = text.rfind("}")
    if first == -1 or last == -1:
        raise ValueError(f"No JSON in auditor response: {text[:200]}")
    return json.loads(text[first:last + 1])


def _parse_findings(raw: Dict) -> List[QualityFinding]:
    findings: List[QualityFinding] = []
    for i, f in enumerate(raw.get("findings", [])):
        try:
            ev_raw = f.get("evidence", {}) or {}
            finding = QualityFinding(
                finding_id=f["finding_id"],
                category=f.get("category", "Unknown"),
                severity=Severity(f["severity"]) if isinstance(f["severity"], str) else f["severity"],
                confidence=float(f["confidence"]),
                evidence=Evidence(
                    file=ev_raw.get("file", "snippet"),
                    line_start=int(ev_raw.get("line_start", 1)),
                    line_end=int(ev_raw.get("line_end", 1)),
                    snippet=ev_raw.get("snippet", ""),
                ),
                rationale=f.get("rationale", ""),
                suggested_refactor=f.get("suggested_refactor", ""),
            )
            findings.append(finding)
        except (ValueError, KeyError, TypeError) as e:
            logger.warning("Dropping malformed quality finding %d: %s", i, e)
            continue
    return findings


def run_code_quality_auditor(state: CodeSentinelState) -> CodeSentinelState:
    code = state.get("input_code", "")
    language = state.get("language", "python")
    prior_feedback = state.get("evaluator_feedback") or ""

    system = _load_system_prompt()
    user = _build_user_prompt(code, language, prior_feedback)

    try:
        response = get_llm().complete(system=system, user=user, max_tokens=3000, temperature=0.0)
        parsed = _extract_json(response)
        findings = _parse_findings(parsed)
    except Exception as e:
        logger.exception("Code Quality Auditor failed: %s", e)
        findings = []
        state["error"] = f"code_quality_auditor: {e}"

    state["quality_findings"] = findings
    trace = state.get("trace", [])
    trace.append(f"code_quality_auditor: produced {len(findings)} finding(s)")
    state["trace"] = trace
    state["evaluator_feedback"] = None
    return state
