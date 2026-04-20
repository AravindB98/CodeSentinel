"""
Security Sentinel agent.

Performs RAG-grounded vulnerability detection. For a given code input:
1. Constructs a retrieval query from language + first N chars of code
2. Retrieves top-K passages from the RAG index
3. Calls the LLM with the security.md system prompt and the retrieved context
4. Parses the response into validated SecurityFinding objects
5. Writes findings + retrieved passages to shared state
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List

from graph.schemas import Evidence, RagSource, SecurityFinding, Severity
from graph.state import CodeSentinelState
from rag.retriever import get_retriever
from utils.llm_client import get_llm

logger = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "security.md"


def _load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _build_query(code: str, language: str) -> str:
    """Build a retrieval query that captures the code's apparent operations."""
    head = code[:800]
    # Keyword extraction: grab suspicious-looking identifiers
    kw = []
    for pat in ["execute", "pickle", "subprocess", "eval", "exec", "yaml",
                "verify=False", "innerHTML", "hashlib", "password", "api_key",
                "Runtime.exec", "ObjectInputStream", "preparedStatement"]:
        if pat.lower() in head.lower():
            kw.append(pat)
    return f"{language} {' '.join(kw)} {head}"


def _format_retrieved_context(passages) -> str:
    """Format passages for the LLM prompt. Format matches what mock evaluator parses."""
    if not passages:
        return "(no passages retrieved)"
    lines = []
    for p in passages:
        lines.append(f"[{p.doc} :: {p.passage_id}]: {p.text}")
    return "\n".join(lines)


def _build_user_prompt(
    code: str, language: str, retrieved_context: str,
    prior_feedback: str = "",
) -> str:
    parts = [
        f"LANGUAGE: {language}",
        "",
        "INPUT CODE:",
        "```" + (language if language != "unknown" else ""),
        code,
        "```",
        "",
        "RETRIEVED CONTEXT (you MUST cite passage_ids from below):",
        retrieved_context,
    ]
    if prior_feedback:
        parts.extend(["", "PRIOR EVALUATOR FEEDBACK (address these before returning):",
                      prior_feedback])
    parts.extend([
        "",
        "Return the findings JSON now. No prose, no markdown fences, just JSON.",
    ])
    return "\n".join(parts)


def _extract_json(text: str) -> Dict:
    """Extract a JSON object from LLM output, tolerating common formatting noise."""
    # Strip markdown fences if present
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    # Find the first {...} block
    first = text.find("{")
    last = text.rfind("}")
    if first == -1 or last == -1 or last <= first:
        raise ValueError(f"No JSON object found in response: {text[:200]}")
    return json.loads(text[first:last + 1])


def _parse_findings(raw: Dict) -> List[SecurityFinding]:
    """Parse the findings array, dropping any that fail schema validation."""
    findings: List[SecurityFinding] = []
    for i, f in enumerate(raw.get("findings", [])):
        try:
            ev_raw = f.get("evidence", {}) or {}
            rs_raw = f.get("rag_source", {}) or {}
            finding = SecurityFinding(
                finding_id=f["finding_id"],
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
                fix=f.get("fix", ""),
                rag_source=RagSource(
                    doc=rs_raw.get("doc", ""),
                    passage_id=rs_raw.get("passage_id", ""),
                    excerpt=rs_raw.get("excerpt"),
                ),
            )
            findings.append(finding)
        except (ValueError, KeyError, TypeError) as e:
            logger.warning("Dropping malformed finding %d: %s", i, e)
            continue
    return findings


def run_security_sentinel(state: CodeSentinelState) -> CodeSentinelState:
    """LangGraph node. Reads input_code, writes security_findings + retrieved_passages."""
    code = state.get("input_code", "")
    language = state.get("language", "python")
    prior_feedback = state.get("evaluator_feedback") or ""

    # Retrieve
    query = _build_query(code, language)
    passages = get_retriever().retrieve(query, k=6)
    state["retrieved_passages"] = [p.as_dict() for p in passages]

    # Call LLM
    system = _load_system_prompt()
    user = _build_user_prompt(code, language, _format_retrieved_context(passages), prior_feedback)
    try:
        response = get_llm().complete(system=system, user=user, max_tokens=4000, temperature=0.0)
        parsed = _extract_json(response)
        findings = _parse_findings(parsed)
    except Exception as e:
        logger.exception("Security Sentinel failed: %s", e)
        findings = []
        state["error"] = f"security_sentinel: {e}"

    state["security_findings"] = findings
    trace = state.get("trace", [])
    trace.append(f"security_sentinel: produced {len(findings)} finding(s)")
    state["trace"] = trace
    # Clear feedback once consumed so next agent sees a clean slate
    state["evaluator_feedback"] = None
    return state
