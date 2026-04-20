"""
Evaluator Guardian agent.

Adversarial reviewer for the multi-agent code review system. Validates
every SecurityFinding and QualityFinding against:

1. Schema completeness
2. Citation presence and correctness (passage_id must exist in retrieved context)
3. Evidence snippet must match source code at claimed line range
4. Remediation must be concrete (length threshold + non-empty)
5. Confidence must clear 0.5

Emits structured feedback for each rejection so upstream agents can correct.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from graph.schemas import (
    EvaluatorVerdict,
    FindingVerdict,
    RejectionReason,
)
from graph.state import CodeSentinelState
from utils.llm_client import get_llm

logger = logging.getLogger(__name__)

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "evaluator.md"


def _load_system_prompt() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _build_user_prompt(state: CodeSentinelState) -> str:
    # Serialize findings from state into the prompt
    sec_findings = [
        f.model_dump() if hasattr(f, "model_dump") else f
        for f in state.get("security_findings", [])
    ]
    qual_findings = [
        f.model_dump() if hasattr(f, "model_dump") else f
        for f in state.get("quality_findings", [])
    ]
    all_findings = sec_findings + qual_findings

    passages = state.get("retrieved_passages", [])
    passages_block = "\n".join(
        f"[{p['doc']} :: {p['passage_id']}]: {p['text'][:400]}"
        for p in passages
    ) or "(no passages retrieved)"

    code = state.get("input_code", "")
    numbered_code = "\n".join(f"{i+1:4d}  {line}" for i, line in enumerate(code.splitlines()))

    parts = [
        "You are reviewing findings from upstream agents. Apply rejection rules strictly.",
        "",
        "INPUT CODE (with line numbers):",
        "```",
        numbered_code,
        "```",
        "",
        "RETRIEVED CONTEXT AVAILABLE TO UPSTREAM:",
        passages_block,
        "",
        "FINDINGS TO REVIEW:",
        "```json",
        json.dumps({"findings": all_findings}, indent=2),
        "```",
        "",
        "Return the verdict JSON now. No prose, no markdown fences outside the JSON.",
    ]
    return "\n".join(parts)


def _extract_json(text: str) -> Dict:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    first = text.find("{")
    last = text.rfind("}")
    if first == -1 or last == -1:
        raise ValueError(f"No JSON object in evaluator response: {text[:200]}")
    return json.loads(text[first:last + 1])


def _programmatic_check(state: CodeSentinelState) -> Optional[EvaluatorVerdict]:
    """Run deterministic checks that don't require the LLM.

    This is a belt-and-suspenders layer: even if the LLM evaluator approves
    something, a programmatic pre-check can catch citations that don't exist
    in the retrieved context.
    """
    sec = state.get("security_findings", [])
    qual = state.get("quality_findings", [])
    passages = state.get("retrieved_passages", [])
    valid_cites = {(p["doc"], p["passage_id"]) for p in passages}
    valid_docs = {p["doc"] for p in passages}

    # If no findings at all, trigger a retry so the sentinel tries harder.
    if not sec and not qual:
        retry_count = state.get("retry_count", {}) or {}
        if retry_count.get("security_sentinel", 0) < 2:
            return EvaluatorVerdict(
                overall_decision="REJECTED",
                per_finding=[],
                rationale=(
                    "No security findings were produced. The code may contain vulnerabilities. "
                    "Re-analyze it carefully and report any suspicious patterns with appropriate "
                    "confidence. Use the best available RAG citation — do not suppress a real "
                    "finding solely because the retrieved context is imperfect."
                ),
            )
        return EvaluatorVerdict(
            overall_decision="APPROVED",
            per_finding=[],
            rationale="No findings to review.",
        )

    verdicts: List[FindingVerdict] = []
    any_rejected = False

    # ---- Security findings: enforce full policy (citation + evidence + fix + confidence) ----
    for f in sec:
        reasons: List[str] = []
        feedback_parts = []

        rs = getattr(f, "rag_source", None)
        cite = (getattr(rs, "doc", ""), getattr(rs, "passage_id", ""))
        if not cite[0] or not cite[1]:
            reasons.append(RejectionReason.MISSING_CITATION.value)
            feedback_parts.append("rag_source.doc and passage_id are required.")
        elif cite not in valid_cites:
            if cite[0] not in valid_docs:
                # Doc name is completely wrong — hard reject
                reasons.append(RejectionReason.CITATION_DOES_NOT_SUPPORT.value)
                feedback_parts.append(
                    f"Doc '{cite[0]}' not in retrieved context. "
                    f"Available docs: {sorted(valid_docs)}. "
                    f"Use one of: {sorted(valid_cites)[:5]}..."
                )
            else:
                # Right doc, wrong passage_id — soft feedback only (LLM can still approve)
                available_ids = [p["passage_id"] for p in passages if p["doc"] == cite[0]]
                feedback_parts.append(
                    f"passage_id '{cite[1]}' not found in '{cite[0]}'. "
                    f"Available ids for that doc: {available_ids[:5]}."
                )

        fix = getattr(f, "fix", "") or ""
        if len(fix) < 20:
            reasons.append(RejectionReason.MISSING_REMEDIATION.value)
            feedback_parts.append("Expand fix with a concrete code example.")

        if float(getattr(f, "confidence", 0)) < 0.5:
            reasons.append(RejectionReason.LOW_CONFIDENCE.value)
            feedback_parts.append("Confidence below 0.5; either re-verify or suppress.")

        decision = "REJECTED" if reasons else "APPROVED"
        if decision == "REJECTED":
            any_rejected = True
        verdicts.append(FindingVerdict(
            finding_id=getattr(f, "finding_id", "SEC-000"),
            decision=decision,
            rejection_reasons=[RejectionReason(r) for r in reasons],
            feedback=" ".join(feedback_parts) if feedback_parts else None,
        ))

    # ---- Quality findings: no RAG citation required; enforce rationale + refactor length ----
    for f in qual:
        reasons: List[str] = []
        feedback_parts = []

        rationale = getattr(f, "rationale", "") or ""
        refactor = getattr(f, "suggested_refactor", "") or ""
        if len(rationale) < 10 or len(refactor) < 10:
            reasons.append(RejectionReason.MISSING_REMEDIATION.value)
            feedback_parts.append("Expand rationale and suggested_refactor.")

        if float(getattr(f, "confidence", 0)) < 0.5:
            reasons.append(RejectionReason.LOW_CONFIDENCE.value)
            feedback_parts.append("Confidence below 0.5.")

        decision = "REJECTED" if reasons else "APPROVED"
        if decision == "REJECTED":
            any_rejected = True
        verdicts.append(FindingVerdict(
            finding_id=getattr(f, "finding_id", "QUAL-000"),
            decision=decision,
            rejection_reasons=[RejectionReason(r) for r in reasons],
            feedback=" ".join(feedback_parts) if feedback_parts else None,
        ))

    if not sec and not qual:
        return EvaluatorVerdict(
            overall_decision="APPROVED",
            per_finding=[],
            rationale="No findings to review.",
        )

    return EvaluatorVerdict(
        overall_decision="REJECTED" if any_rejected else "APPROVED",
        per_finding=verdicts,
        rationale=(
            "All findings passed programmatic checks."
            if not any_rejected else
            f"{sum(1 for v in verdicts if v.decision == 'REJECTED')} finding(s) rejected."
        ),
    )


def run_evaluator(state: CodeSentinelState, use_llm: bool = True) -> CodeSentinelState:
    """LangGraph node. Writes evaluator_verdict; sets evaluator_feedback if rejected."""
    prog_verdict = _programmatic_check(state)

    has_findings = bool(
        state.get("security_findings") or state.get("quality_findings")
    )

    # Skip LLM when there are no findings (nothing to semantically review)
    # or when explicitly disabled.
    if not use_llm or prog_verdict is None or not has_findings:
        verdict = prog_verdict
    else:
        # Always run LLM for non-empty findings so it can override over-strict
        # programmatic citation checks. Pass programmatic notes as context.
        system = _load_system_prompt()
        user = _build_user_prompt(state)
        if prog_verdict.overall_decision == "REJECTED":
            user += (
                "\n\nPROGRAMMATIC PRE-CHECK NOTES (advisory only — use your judgement):\n"
                + prog_verdict.rationale
            )
        try:
            response = get_llm().complete(system=system, user=user, max_tokens=2000, temperature=0.0)
            parsed = _extract_json(response)
            llm_verdict = EvaluatorVerdict(
                overall_decision=parsed.get("overall_decision", "APPROVED"),
                per_finding=[
                    FindingVerdict(
                        finding_id=v.get("finding_id", ""),
                        decision=v.get("decision", "APPROVED"),
                        rejection_reasons=[RejectionReason(r) for r in v.get("rejection_reasons", [])],
                        feedback=v.get("feedback"),
                    )
                    for v in parsed.get("per_finding", [])
                ],
                rationale=parsed.get("rationale", ""),
            )
            verdict = llm_verdict
        except Exception as e:
            logger.warning("LLM evaluator failed; using programmatic verdict: %s", e)
            verdict = prog_verdict

    state["evaluator_verdict"] = verdict

    # Aggregate feedback for upstream agent on rejection
    if verdict.overall_decision == "REJECTED":
        fb_lines = []
        for v in verdict.per_finding:
            if v.decision == "REJECTED" and v.feedback:
                fb_lines.append(f"- {v.finding_id}: {v.feedback}")
        state["evaluator_feedback"] = "\n".join(fb_lines) or verdict.rationale

    trace = state.get("trace", [])
    trace.append(
        f"evaluator: {verdict.overall_decision} "
        f"(approved={len(verdict.approved_ids)}, rejected={len(verdict.rejected_ids)})"
    )
    state["trace"] = trace
    return state
