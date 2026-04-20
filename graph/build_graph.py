"""
Build the CodeSentinel multi-agent graph.

Primary backend: LangGraph StateGraph with conditional routing and a
per-agent retry counter acting as a circuit breaker. This is what runs
in production.

Fallback backend: a hand-rolled sequential executor that honors the same
retry-and-reroute semantics, used when langgraph is unavailable
(e.g., during tests or in minimal environments). Behavior is identical
at the semantic level.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict

from graph.agents.code_quality_auditor import run_code_quality_auditor
from graph.agents.evaluator_guardian import run_evaluator
from graph.agents.security_sentinel import run_security_sentinel
from graph.state import CodeSentinelState

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


# ---- Node wrappers that increment retry counter ----

def _with_retry_counter(name: str, fn: Callable[[CodeSentinelState], CodeSentinelState]):
    def wrapped(state: CodeSentinelState) -> CodeSentinelState:
        counter = state.get("retry_count", {}) or {}
        counter[name] = counter.get(name, 0) + 1
        state["retry_count"] = counter
        return fn(state)
    return wrapped


def _route_after_evaluator(state: CodeSentinelState) -> str:
    """Conditional edge decision function."""
    verdict = state.get("evaluator_verdict")
    if verdict is None or verdict.overall_decision == "APPROVED":
        return "assemble_report"

    counter = state.get("retry_count", {}) or {}
    if counter.get("security_sentinel", 0) >= MAX_RETRIES:
        trace = state.get("trace", [])
        trace.append("circuit_breaker: max retries reached, terminating")
        state["trace"] = trace
        return "assemble_report"
    return "security_sentinel"  # reroute


def assemble_report(state: CodeSentinelState) -> CodeSentinelState:
    """Final node: build a human-readable markdown report from approved findings."""
    sec = state.get("security_findings", []) or []
    qual = state.get("quality_findings", []) or []
    verdict = state.get("evaluator_verdict")
    circuit_breaker_fired = any(
        "circuit_breaker" in t for t in state.get("trace", [])
    )
    if circuit_breaker_fired:
        # Max retries exhausted — pass through all findings so users see something
        approved = {f.finding_id for f in sec}
    elif verdict:
        approved = set(verdict.approved_ids)
    else:
        approved = {f.finding_id for f in sec}

    lines = ["# CodeSentinel Review Report", ""]

    # Summary
    sec_count = sum(1 for f in sec if f.finding_id in approved)
    qual_count = len(qual)
    lines.append(f"**Security findings:** {sec_count}")
    lines.append(f"**Quality findings:** {qual_count}")
    if verdict:
        lines.append(f"**Evaluator verdict:** {verdict.overall_decision}")
        if verdict.rejected_ids:
            lines.append(f"**Rejected by Evaluator:** {', '.join(verdict.rejected_ids)}")
    lines.append("")

    # Security findings
    if sec_count > 0:
        lines.append("## Security Findings")
        lines.append("")
        for f in sec:
            if f.finding_id not in approved:
                continue
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines.extend([
                f"### {f.finding_id} {f.category} ({sev})",
                f"- **CWE:** {f.cwe_id}",
                f"- **OWASP:** {f.owasp_ref}",
                f"- **Confidence:** {f.confidence:.2f}",
                f"- **Lines:** {f.evidence.line_start}-{f.evidence.line_end}",
                "",
                "**Evidence:**",
                "```",
                f.evidence.snippet,
                "```",
                "",
                f"**Fix:** {f.fix}",
                "",
                f"**Citation:** {f.rag_source.doc} :: {f.rag_source.passage_id}",
                "",
            ])

    if qual_count > 0:
        lines.append("## Quality Findings")
        lines.append("")
        for f in qual:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines.extend([
                f"### {f.finding_id} {f.category} ({sev})",
                f"- **Lines:** {f.evidence.line_start}-{f.evidence.line_end}",
                "",
                f"**Rationale:** {f.rationale}",
                "",
                f"**Refactor:** {f.suggested_refactor}",
                "",
            ])

    if sec_count == 0 and qual_count == 0:
        lines.append("No issues found.")

    state["final_report"] = "\n".join(lines)
    trace = state.get("trace", [])
    trace.append("assemble_report: done")
    state["trace"] = trace
    return state


# ---- LangGraph construction ----

def build_langgraph():
    """Build the production LangGraph StateGraph. Returns a compiled graph."""
    from langgraph.graph import StateGraph, END

    # Wrap nodes with retry counter
    sec_node = _with_retry_counter("security_sentinel", run_security_sentinel)
    qual_node = _with_retry_counter("code_quality_auditor", run_code_quality_auditor)
    eval_node = _with_retry_counter("evaluator", run_evaluator)

    # Use CodeSentinelState (TypedDict) so LangGraph passes the full state snapshot
    # to every node, not just individually-changed channels.
    g = StateGraph(CodeSentinelState)
    g.add_node("security_sentinel", sec_node)
    g.add_node("code_quality_auditor", qual_node)
    g.add_node("evaluator", eval_node)
    g.add_node("assemble_report", assemble_report)

    g.set_entry_point("security_sentinel")
    g.add_edge("security_sentinel", "code_quality_auditor")
    g.add_edge("code_quality_auditor", "evaluator")
    g.add_conditional_edges("evaluator", _route_after_evaluator, {
        "security_sentinel": "security_sentinel",
        "assemble_report": "assemble_report",
    })
    g.add_edge("assemble_report", END)
    return g.compile()


def build_fallback_runner():
    """Hand-rolled executor with identical routing semantics.

    Used when langgraph is not installed. Provides the same observable
    behavior (sequential agents, conditional retry, bounded circuit breaker).
    """
    def run(state: CodeSentinelState) -> CodeSentinelState:
        state.setdefault("retry_count", {})
        state.setdefault("trace", [])
        state.setdefault("evaluator_feedback", None)

        while True:
            # Security Sentinel
            counter = state.get("retry_count", {})
            counter["security_sentinel"] = counter.get("security_sentinel", 0) + 1
            state["retry_count"] = counter
            state = run_security_sentinel(state)

            # Code Quality Auditor (once per outer iteration, idempotent)
            counter = state.get("retry_count", {})
            counter["code_quality_auditor"] = counter.get("code_quality_auditor", 0) + 1
            state["retry_count"] = counter
            state = run_code_quality_auditor(state)

            # Evaluator
            counter = state.get("retry_count", {})
            counter["evaluator"] = counter.get("evaluator", 0) + 1
            state["retry_count"] = counter
            state = run_evaluator(state)

            # Route
            decision = _route_after_evaluator(state)
            if decision == "assemble_report":
                return assemble_report(state)
            # else: retry (loop continues)
    return run


def build_graph():
    """Return the best available runner.

    Returns an object with an `invoke(state)` method, matching LangGraph's
    compiled-graph interface so callers don't need to branch.
    """
    try:
        return build_langgraph()
    except ImportError:
        logger.info("langgraph not installed; using fallback runner")
        runner = build_fallback_runner()

        class _Runner:
            def invoke(self, state: CodeSentinelState) -> CodeSentinelState:
                return runner(state)

        return _Runner()
