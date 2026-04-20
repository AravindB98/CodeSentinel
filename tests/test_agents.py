"""Tests for individual agents. Run with CODESENTINEL_MOCK_LLM=1."""
from __future__ import annotations

import os
from contextlib import contextmanager

os.environ["CODESENTINEL_MOCK_LLM"] = "1"


@contextmanager
def raises(exc_type):
    """pytest.raises shim that also works under plain unittest/direct-call."""
    try:
        yield
    except exc_type:
        return
    except Exception as e:
        raise AssertionError(f"expected {exc_type.__name__}, got {type(e).__name__}: {e}")
    else:
        raise AssertionError(f"expected {exc_type.__name__} to be raised, nothing was raised")


from graph.agents.code_quality_auditor import run_code_quality_auditor  # noqa: E402
from graph.agents.evaluator_guardian import (  # noqa: E402
    _programmatic_check,
    run_evaluator,
)
from graph.agents.security_sentinel import run_security_sentinel  # noqa: E402
from graph.schemas import Severity  # noqa: E402


VULNERABLE_PY = '''import sqlite3, pickle
from flask import Flask, request
app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchone()

@app.route("/restore", methods=["POST"])
def restore():
    return pickle.loads(request.data)
'''

CLEAN_PY = '''import sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    with sqlite3.connect("users.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()
'''


# --- Security Sentinel ---

def test_security_sentinel_detects_sql_injection():
    state = {"input_code": VULNERABLE_PY, "language": "python"}
    state = run_security_sentinel(state)
    findings = state.get("security_findings", [])
    cwes = [f.cwe_id for f in findings]
    assert "CWE-89" in cwes


def test_security_sentinel_detects_pickle():
    state = {"input_code": VULNERABLE_PY, "language": "python"}
    state = run_security_sentinel(state)
    findings = state.get("security_findings", [])
    cwes = [f.cwe_id for f in findings]
    assert "CWE-502" in cwes


def test_security_sentinel_no_findings_on_clean_code():
    state = {"input_code": CLEAN_PY, "language": "python"}
    state = run_security_sentinel(state)
    findings = state.get("security_findings", [])
    assert len(findings) == 0


def test_security_sentinel_findings_have_citations():
    state = {"input_code": VULNERABLE_PY, "language": "python"}
    state = run_security_sentinel(state)
    for f in state["security_findings"]:
        assert f.rag_source.doc
        assert f.rag_source.passage_id


def test_security_sentinel_findings_have_concrete_fixes():
    state = {"input_code": VULNERABLE_PY, "language": "python"}
    state = run_security_sentinel(state)
    for f in state["security_findings"]:
        assert len(f.fix) >= 20


# --- Code Quality Auditor ---

def test_quality_auditor_detects_module_db_connection():
    code = "import sqlite3\nconn = sqlite3.connect('users.db')\n"
    state = {"input_code": code, "language": "python"}
    state = run_code_quality_auditor(state)
    findings = state.get("quality_findings", [])
    assert len(findings) >= 1
    assert any("Resource Management" in f.category for f in findings)


def test_quality_auditor_detects_bare_except():
    code = "try:\n    x()\nexcept:\n    pass\n"
    state = {"input_code": code, "language": "python"}
    state = run_code_quality_auditor(state)
    findings = state.get("quality_findings", [])
    assert any("Error Handling" in f.category for f in findings)


def test_quality_auditor_does_not_flag_security():
    state = {"input_code": VULNERABLE_PY, "language": "python"}
    state = run_code_quality_auditor(state)
    for f in state.get("quality_findings", []):
        assert f.severity != Severity.CRITICAL, "quality auditor must never produce CRITICAL"


# --- Evaluator ---

def test_evaluator_approves_well_formed_findings():
    # First get findings via Security Sentinel
    state = {"input_code": VULNERABLE_PY, "language": "python"}
    state = run_security_sentinel(state)
    state = run_evaluator(state, use_llm=False)
    verdict = state["evaluator_verdict"]
    assert verdict.overall_decision == "APPROVED"


def test_evaluator_rejects_missing_citation():
    """Manually construct a finding with no rag_source and verify rejection."""
    from graph.schemas import Evidence, RagSource, SecurityFinding

    bad_finding = SecurityFinding(
        finding_id="SEC-001", category="Injection", cwe_id="CWE-89",
        owasp_ref="A03:2025", severity=Severity.CRITICAL, confidence=0.9,
        evidence=Evidence(file="x", line_start=1, line_end=1, snippet="cur.execute(f'...')"),
        fix="Use parameterized queries with placeholders always.",
        rag_source=RagSource(doc="nonexistent.md", passage_id="FAKE-01"),
    )
    state = {
        "input_code": "cur.execute(f'...')",
        "language": "python",
        "security_findings": [bad_finding],
        "retrieved_passages": [
            {"doc": "patterns.md", "passage_id": "PY-01", "text": "SQL injection pattern",
             "score": 0.9}
        ],
    }
    verdict = _programmatic_check(state)
    assert verdict.overall_decision == "REJECTED"
    assert verdict.rejected_ids == ["SEC-001"]


def test_evaluator_rejects_short_remediation():
    """Pydantic/dataclass validation should reject a finding with fix<20 chars at construction."""
    from graph.schemas import Evidence, RagSource, SecurityFinding

    # Constructing a SecurityFinding with a fix shorter than 20 chars must raise.
    with raises(ValueError):
        SecurityFinding(
            finding_id="SEC-002", category="Injection", cwe_id="CWE-89", owasp_ref="A03:2025",
            severity=Severity.CRITICAL, confidence=0.9,
            evidence=Evidence(file="x", line_start=1, line_end=1, snippet="..."),
            fix="short",  # too short
            rag_source=RagSource(doc="patterns.md", passage_id="PY-01"),
        )


def test_evaluator_low_confidence_rejection():
    from graph.schemas import Evidence, RagSource, SecurityFinding

    bad = SecurityFinding(
        finding_id="SEC-001", category="Injection", cwe_id="CWE-89", owasp_ref="A03:2025",
        severity=Severity.MEDIUM, confidence=0.3,  # below threshold
        evidence=Evidence(file="x", line_start=1, line_end=1, snippet="code"),
        fix="Use parameterized queries always to fix this.",
        rag_source=RagSource(doc="patterns.md", passage_id="PY-01"),
    )
    state = {
        "input_code": "code", "language": "python",
        "security_findings": [bad],
        "retrieved_passages": [{"doc": "patterns.md", "passage_id": "PY-01",
                                "text": "SQL pattern", "score": 0.9}],
    }
    verdict = _programmatic_check(state)
    assert verdict.overall_decision == "REJECTED"


def test_evaluator_empty_findings_approves():
    state = {"input_code": "", "language": "python",
             "security_findings": [], "retrieved_passages": []}
    verdict = _programmatic_check(state)
    assert verdict.overall_decision == "APPROVED"
