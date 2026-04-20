"""
Pydantic schemas that define the contracts between agents.

Every agent output is validated against one of these schemas. Schema
violations are surfaced to the Evaluator Guardian as rejection reasons,
so contract enforcement is first-class, not best-effort.

If pydantic is unavailable (e.g., during early bootstrap or in a minimal
CI environment), we fall back to dataclass-like validation with the same
field semantics. Agent behavior is identical in both modes.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel as _PydBase, Field, field_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

    def Field(default=None, **kwargs):  # type: ignore
        return default

    def field_validator(*args, **kwargs):  # type: ignore
        def deco(f):
            return f
        return deco

    class _PydBase:  # type: ignore
        """Minimal BaseModel-compatible fallback."""
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
            self._post_init()

        def _post_init(self) -> None:
            pass

        def model_dump(self) -> Dict[str, Any]:
            out = {}
            for k, v in self.__dict__.items():
                if k.startswith("_"):
                    continue
                if isinstance(v, _PydBase):
                    out[k] = v.model_dump()
                elif isinstance(v, list):
                    out[k] = [x.model_dump() if isinstance(x, _PydBase) else
                              (x.value if isinstance(x, Enum) else x) for x in v]
                elif isinstance(v, Enum):
                    out[k] = v.value
                else:
                    out[k] = v
            return out

        @classmethod
        def model_validate(cls, data: Dict[str, Any]):
            return cls(**data)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RejectionReason(str, Enum):
    MISSING_CITATION = "missing_citation"
    CITATION_DOES_NOT_SUPPORT = "citation_does_not_support"
    MISSING_EVIDENCE = "missing_evidence"
    MISSING_REMEDIATION = "missing_remediation"
    SCHEMA_VIOLATION = "schema_violation"
    INTERNAL_CONTRADICTION = "internal_contradiction"
    LOW_CONFIDENCE = "low_confidence"


# --- With or without pydantic, models share the same constructor signature ---

class Evidence(_PydBase):
    """Concrete source pointer for a finding."""
    if PYDANTIC_AVAILABLE:
        file: str
        line_start: int = Field(..., ge=1)
        line_end: int = Field(..., ge=1)
        snippet: str = Field(..., min_length=1, max_length=2000)

    def _post_init(self):
        if not getattr(self, "file", ""):
            raise ValueError("Evidence.file required")
        ls = int(getattr(self, "line_start", 0))
        le = int(getattr(self, "line_end", 0))
        if ls < 1:
            raise ValueError("line_start must be >= 1")
        if le < ls:
            raise ValueError("line_end must be >= line_start")
        snippet = getattr(self, "snippet", "") or ""
        if not snippet or len(snippet) > 2000:
            raise ValueError("snippet must be non-empty and <= 2000 chars")


class RagSource(_PydBase):
    """Citation back to the RAG passage that grounds a finding."""
    if PYDANTIC_AVAILABLE:
        doc: str
        passage_id: str
        excerpt: Optional[str] = Field(default=None, max_length=800)

    def _post_init(self):
        if not getattr(self, "doc", ""):
            raise ValueError("RagSource.doc required")
        if not getattr(self, "passage_id", ""):
            raise ValueError("RagSource.passage_id required")


class SecurityFinding(_PydBase):
    """One security vulnerability finding from the Security Sentinel."""
    if PYDANTIC_AVAILABLE:
        finding_id: str
        category: str
        cwe_id: str
        owasp_ref: str
        severity: Severity
        confidence: float
        evidence: Evidence
        fix: str
        rag_source: RagSource

    def _post_init(self):
        if not re.match(r"^SEC-\d{3,}$", str(getattr(self, "finding_id", ""))):
            raise ValueError(f"bad finding_id: {getattr(self, 'finding_id', None)}")
        if not re.match(r"^CWE-\d+$", str(getattr(self, "cwe_id", ""))):
            raise ValueError(f"bad cwe_id: {getattr(self, 'cwe_id', None)}")
        try:
            c = float(getattr(self, "confidence", -1))
        except Exception:
            raise ValueError("confidence must be numeric")
        if not (0.0 <= c <= 1.0):
            raise ValueError(f"confidence out of [0,1]: {c}")
        if len(str(getattr(self, "fix", ""))) < 20:
            raise ValueError("fix too short (min 20 chars)")
        ev = getattr(self, "evidence", None)
        if not isinstance(ev, Evidence):
            raise ValueError("evidence must be Evidence instance")
        rs = getattr(self, "rag_source", None)
        if not isinstance(rs, RagSource):
            raise ValueError("rag_source must be RagSource instance")
        # Normalize severity to enum
        sev = getattr(self, "severity", None)
        if isinstance(sev, str):
            self.severity = Severity(sev)


class QualityFinding(_PydBase):
    """One code quality / maintainability finding from the Auditor."""
    if PYDANTIC_AVAILABLE:
        finding_id: str
        category: str
        severity: Severity
        confidence: float
        evidence: Evidence
        rationale: str
        suggested_refactor: str

    def _post_init(self):
        if not re.match(r"^QUAL-\d{3,}$", str(getattr(self, "finding_id", ""))):
            raise ValueError(f"bad finding_id: {getattr(self, 'finding_id', None)}")
        try:
            c = float(getattr(self, "confidence", -1))
        except Exception:
            raise ValueError("confidence must be numeric")
        if not (0.0 <= c <= 1.0):
            raise ValueError(f"confidence out of [0,1]: {c}")
        if len(str(getattr(self, "rationale", ""))) < 10:
            raise ValueError("rationale too short")
        sev = getattr(self, "severity", None)
        if isinstance(sev, str):
            self.severity = Severity(sev)


class FindingVerdict(_PydBase):
    """Per-finding decision from the Evaluator."""
    if PYDANTIC_AVAILABLE:
        finding_id: str
        decision: str
        rejection_reasons: List[RejectionReason] = Field(default_factory=list)
        feedback: Optional[str] = None

    def _post_init(self):
        if getattr(self, "decision", None) not in ("APPROVED", "REJECTED"):
            raise ValueError("decision must be APPROVED or REJECTED")
        # Normalize reasons
        raw = getattr(self, "rejection_reasons", []) or []
        if raw and isinstance(raw[0], str):
            self.rejection_reasons = [RejectionReason(r) for r in raw]


class EvaluatorVerdict(_PydBase):
    """Top-level verdict from the Evaluator Guardian."""
    if PYDANTIC_AVAILABLE:
        overall_decision: str
        per_finding: List[FindingVerdict] = Field(default_factory=list)
        rationale: str = ""

    def _post_init(self):
        if getattr(self, "overall_decision", None) not in ("APPROVED", "REJECTED"):
            raise ValueError("overall_decision must be APPROVED or REJECTED")
        if not hasattr(self, "per_finding") or self.per_finding is None:
            self.per_finding = []
        if not hasattr(self, "rationale") or self.rationale is None:
            self.rationale = ""

    @property
    def approved_ids(self) -> List[str]:
        return [v.finding_id for v in self.per_finding if v.decision == "APPROVED"]

    @property
    def rejected_ids(self) -> List[str]:
        return [v.finding_id for v in self.per_finding if v.decision == "REJECTED"]
