"""
Shared state object that flows through the LangGraph.

LangGraph nodes read from and write to this TypedDict. Making the state
explicit and strongly typed is what makes the system testable and
reproducible. Nothing is passed implicitly between agents.
"""
from __future__ import annotations

from typing import Dict, List, Optional, TypedDict

from graph.schemas import (
    EvaluatorVerdict,
    QualityFinding,
    SecurityFinding,
)


class RetrievedPassage(TypedDict):
    """One passage returned from the RAG retriever."""
    doc: str
    passage_id: str
    text: str
    score: float


class CodeSentinelState(TypedDict, total=False):
    # --- Inputs ---
    input_code: str
    language: str  # "python" | "javascript" | "java" | "unknown"

    # --- RAG ---
    retrieved_passages: List[RetrievedPassage]

    # --- Findings ---
    security_findings: List[SecurityFinding]
    quality_findings: List[QualityFinding]

    # --- Evaluation ---
    evaluator_verdict: Optional[EvaluatorVerdict]
    retry_count: Dict[str, int]  # agent_name -> retry count
    evaluator_feedback: Optional[str]  # feedback routed back to upstream

    # --- Output ---
    final_report: Optional[str]
    run_id: str

    # --- Diagnostics ---
    trace: List[str]  # one entry per graph transition
    error: Optional[str]
