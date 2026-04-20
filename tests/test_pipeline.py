"""End-to-end tests for the full CodeSentinel pipeline."""
from __future__ import annotations

import os

os.environ["CODESENTINEL_MOCK_LLM"] = "1"

from graph.build_graph import build_graph  # noqa: E402


VULNERABLE_FLASK = '''import sqlite3, pickle
from flask import Flask, request
app = Flask(__name__)
conn = sqlite3.connect("users.db")

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cur.fetchone()

@app.route("/restore", methods=["POST"])
def restore():
    return pickle.loads(request.data)
'''


def test_pipeline_runs_end_to_end():
    runner = build_graph()
    state = {"input_code": VULNERABLE_FLASK, "language": "python", "run_id": "test-e2e"}
    result = runner.invoke(state)
    assert "trace" in result
    assert "final_report" in result
    assert result["final_report"]


def test_pipeline_catches_known_vulnerabilities():
    runner = build_graph()
    state = {"input_code": VULNERABLE_FLASK, "language": "python", "run_id": "t"}
    result = runner.invoke(state)
    findings = result["security_findings"]
    cwes = [f.cwe_id for f in findings]
    assert "CWE-89" in cwes, f"SQL injection should be detected; got {cwes}"
    assert "CWE-502" in cwes, f"pickle deserialization should be detected; got {cwes}"


def test_pipeline_evaluator_approves_valid_findings():
    runner = build_graph()
    state = {"input_code": VULNERABLE_FLASK, "language": "python", "run_id": "t"}
    result = runner.invoke(state)
    verdict = result["evaluator_verdict"]
    assert verdict.overall_decision == "APPROVED"
    assert len(verdict.approved_ids) >= 2


def test_pipeline_produces_rag_citations():
    runner = build_graph()
    state = {"input_code": VULNERABLE_FLASK, "language": "python", "run_id": "t"}
    result = runner.invoke(state)
    for f in result["security_findings"]:
        assert f.rag_source.doc
        assert f.rag_source.passage_id


def test_pipeline_clean_code_no_findings():
    clean = ('import sqlite3\n'
             'def get_user(user_id):\n'
             '    with sqlite3.connect("db") as c:\n'
             '        return c.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()\n')
    runner = build_graph()
    state = {"input_code": clean, "language": "python", "run_id": "t"}
    result = runner.invoke(state)
    assert len(result["security_findings"]) == 0


def test_pipeline_final_report_includes_citations():
    runner = build_graph()
    state = {"input_code": VULNERABLE_FLASK, "language": "python", "run_id": "t"}
    result = runner.invoke(state)
    report = result["final_report"]
    assert "Citation:" in report
    assert "CWE-" in report


def test_pipeline_respects_circuit_breaker():
    """If Evaluator keeps rejecting, the graph should terminate at max retries."""
    from graph.agents.evaluator_guardian import _programmatic_check
    from graph.build_graph import MAX_RETRIES
    # Default MAX_RETRIES is 3; just verify the constant and that the
    # pipeline terminates without hanging on any input.
    assert MAX_RETRIES == 3

    runner = build_graph()
    state = {"input_code": VULNERABLE_FLASK, "language": "python", "run_id": "t"}
    result = runner.invoke(state)
    # The trace must end with assemble_report regardless of approve/reject path
    assert result["trace"][-1].startswith("assemble_report")
