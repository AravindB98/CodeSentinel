"""
CodeSentinel Streamlit UI.

Paste code or upload a file, hit Analyze, and see the full multi-agent
review with per-finding citations and the Evaluator's verdict.

Run:
    streamlit run app/streamlit_app.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure project root on path when run via streamlit
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import os

import streamlit as st  # noqa: E402

# On Streamlit Cloud the API key lives in st.secrets; expose it as an env var
# so the rest of the codebase (utils/llm_client.py) picks it up transparently.
_api_key = st.secrets.get("ANTHROPIC_API_KEY", "") or os.getenv("ANTHROPIC_API_KEY", "")
if _api_key:
    os.environ["ANTHROPIC_API_KEY"] = _api_key

from graph.build_graph import build_graph  # noqa: E402


@st.cache_resource(show_spinner="Building RAG index…")
def _ensure_rag_index():
    """Build the RAG index on first run (needed on Streamlit Cloud)."""
    from rag.retriever import get_retriever
    try:
        get_retriever()
    except RuntimeError:
        from rag.ingest import main as ingest_main
        ingest_main()


_ensure_rag_index()

st.set_page_config(
    page_title="CodeSentinel",
    page_icon="🔒",
    layout="wide",
)

st.markdown(
    """
    <style>
    .main > div { padding-top: 1rem; }
    .finding-card { border-left: 4px solid #ef4444; padding: 12px 16px;
                    background: #1a1a1a; border-radius: 0 6px 6px 0; margin-bottom: 12px; }
    .finding-card.medium { border-left-color: #f59e0b; }
    .finding-card.low { border-left-color: #10b981; }
    .small-code { font-family: monospace; font-size: 0.85em; background: #0f0f0f;
                  padding: 8px 12px; border-radius: 4px; color: #d4d4d4; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 999px;
             font-size: 0.75em; font-weight: 600; margin-right: 6px; }
    .badge-crit { background: #7f1d1d; color: #fecaca; }
    .badge-high { background: #78350f; color: #fed7aa; }
    .badge-med { background: #713f12; color: #fef3c7; }
    .badge-low { background: #14532d; color: #bbf7d0; }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Sidebar ---
with st.sidebar:
    st.title("🔒 CodeSentinel")
    st.markdown(
        "**Multi-agent AI code review.**\n\n"
        "Security Sentinel, Code Quality Auditor, and Evaluator Guardian "
        "review your code together. Every finding is cited against OWASP "
        "Top 10 2025 and CWE."
    )
    st.divider()
    st.caption("INFO 7375 Final Project · Spring 2026")
    st.caption("Aravind Balaji · Northeastern University")
    st.divider()
    st.markdown("### Example Snippets")
    examples = {
        "Vulnerable Flask endpoint":
            'import sqlite3, pickle\n'
            'from flask import Flask, request\n'
            'app = Flask(__name__)\n'
            'conn = sqlite3.connect("users.db")\n\n'
            '@app.route("/user")\n'
            'def get_user():\n'
            '    user_id = request.args.get("id")\n'
            '    cur = conn.cursor()\n'
            '    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            '    return cur.fetchone()\n\n'
            '@app.route("/restore", methods=["POST"])\n'
            'def restore_session():\n'
            '    return pickle.loads(request.data)\n',
        "Clean Flask endpoint":
            'import sqlite3\n'
            'from flask import Flask, request\n'
            'app = Flask(__name__)\n\n'
            '@app.route("/user")\n'
            'def get_user():\n'
            '    user_id = request.args.get("id")\n'
            '    with sqlite3.connect("users.db") as conn:\n'
            '        cur = conn.cursor()\n'
            '        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
            '        return cur.fetchone()\n',
        "Command injection":
            'import subprocess\n'
            'from flask import request\n\n'
            'def list_dir():\n'
            '    path = request.args.get("path", ".")\n'
            '    return subprocess.run(f"ls {path}", shell=True, capture_output=True)\n',
        "JS SQL injection":
            "const mysql = require('mysql');\n"
            "const db = mysql.createConnection({host: 'localhost'});\n\n"
            "app.get('/user', (req, res) => {\n"
            "  const userId = req.query.id;\n"
            "  db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, rows) => {\n"
            "    res.json(rows);\n"
            "  });\n"
            "});\n",
    }
    example_choice = st.selectbox("Load an example", ["(none)"] + list(examples.keys()))


# --- Main input panel ---
st.title("Multi-agent AI code review")
st.caption(
    "Three specialized agents review your code together: Security Sentinel "
    "(OWASP/CWE-grounded), Code Quality Auditor, and Evaluator Guardian."
)

col_in, col_cfg = st.columns([3, 1])

with col_cfg:
    language = st.selectbox("Language", ["python", "javascript", "java", "unknown"])
    use_llm_eval = st.checkbox("LLM Evaluator (slower)", value=False,
                                help="Programmatic evaluator runs always; LLM layer adds semantic review.")
    uploaded = st.file_uploader("Or upload a source file", type=["py", "js", "java", "ts"])

default_code = examples.get(example_choice, "")
if uploaded is not None:
    try:
        default_code = uploaded.read().decode("utf-8", errors="replace")
    except Exception as e:
        st.error(f"Could not read file: {e}")

with col_in:
    code = st.text_area(
        "Paste code here",
        value=default_code,
        height=360,
        placeholder="Paste the code you want reviewed...",
    )

analyze = st.button("🔍 Analyze", type="primary", use_container_width=True)
st.divider()

# --- Analysis ---
if analyze:
    if not code.strip():
        st.warning("Please paste some code first.")
        st.stop()

    with st.spinner("Building graph..."):
        runner = build_graph()

    progress_ph = st.empty()
    t0 = time.time()
    progress_ph.info("Security Sentinel analyzing...")

    state = {
        "input_code": code,
        "language": language,
        "run_id": f"ui-{int(time.time())}",
    }
    try:
        result = runner.invoke(state)
    except Exception as e:
        st.error(f"Pipeline error: {e}")
        st.stop()

    elapsed = time.time() - t0
    progress_ph.empty()

    sec = result.get("security_findings", []) or []
    qual = result.get("quality_findings", []) or []
    verdict = result.get("evaluator_verdict")
    passages = result.get("retrieved_passages", []) or []
    trace = result.get("trace", []) or []

    approved = set(verdict.approved_ids) if verdict else {f.finding_id for f in sec + qual}

    # Top-line metrics
    m1, m2, m3, m4 = st.columns(4)
    sec_app = [f for f in sec if f.finding_id in approved]
    qual_app = [f for f in qual if f.finding_id in approved]
    m1.metric("Security findings", len(sec_app))
    m2.metric("Quality findings", len(qual_app))
    m3.metric("Evaluator verdict",
              verdict.overall_decision if verdict else "n/a")
    m4.metric("Runtime", f"{elapsed:.2f}s")

    # Tabs
    t_findings, t_evaluator, t_rag, t_trace = st.tabs(
        ["Findings", "Evaluator", "RAG Context", "Trace"]
    )

    def sev_badge(sev) -> str:
        sev_val = sev.value if hasattr(sev, "value") else str(sev)
        cls = {
            "CRITICAL": "badge-crit", "HIGH": "badge-high",
            "MEDIUM": "badge-med", "LOW": "badge-low", "INFO": "badge-low",
        }.get(sev_val, "badge-low")
        return f'<span class="badge {cls}">{sev_val}</span>'

    with t_findings:
        if not sec_app and not qual_app:
            st.success("No approved findings. Code looks clean on this pass.")
        else:
            if sec_app:
                st.subheader("Security findings")
                for f in sec_app:
                    sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    card_cls = "finding-card"
                    if sev_val in ("MEDIUM",):
                        card_cls += " medium"
                    elif sev_val in ("LOW", "INFO"):
                        card_cls += " low"
                    st.markdown(
                        f"""
                        <div class="{card_cls}">
                            <div>{sev_badge(f.severity)}
                                <strong>{f.finding_id}</strong> &mdash; {f.category}
                                <span style="color:#a3a3a3; font-size:0.85em;">
                                    ({f.cwe_id} · {f.owasp_ref} · confidence {f.confidence:.2f} ·
                                    lines {f.evidence.line_start}-{f.evidence.line_end})
                                </span>
                            </div>
                            <div class="small-code">{_safe(f.evidence.snippet)}</div>
                            <div style="margin-top:8px;"><strong>Fix:</strong> {_safe(f.fix)}</div>
                            <div style="margin-top:6px; font-size:0.8em; color:#737373;">
                                Cited: {f.rag_source.doc} :: {f.rag_source.passage_id}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            if qual_app:
                st.subheader("Quality findings")
                for f in qual_app:
                    st.markdown(
                        f"""
                        <div class="finding-card medium">
                            <div>{sev_badge(f.severity)}
                                <strong>{f.finding_id}</strong> &mdash; {f.category}
                                <span style="color:#a3a3a3; font-size:0.85em;">
                                    (confidence {f.confidence:.2f} ·
                                    lines {f.evidence.line_start}-{f.evidence.line_end})
                                </span>
                            </div>
                            <div class="small-code">{_safe(f.evidence.snippet)}</div>
                            <div style="margin-top:8px;"><strong>Rationale:</strong> {_safe(f.rationale)}</div>
                            <div style="margin-top:6px;"><strong>Refactor:</strong> {_safe(f.suggested_refactor)}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

    with t_evaluator:
        if verdict is None:
            st.info("No evaluator verdict recorded.")
        else:
            if verdict.overall_decision == "APPROVED":
                st.success(f"Verdict: {verdict.overall_decision}")
            else:
                st.warning(f"Verdict: {verdict.overall_decision}")
            st.write(verdict.rationale)
            st.divider()
            for v in verdict.per_finding:
                reasons = [r.value if hasattr(r, "value") else str(r) for r in v.rejection_reasons]
                if v.decision == "APPROVED":
                    st.success(f"{v.finding_id}: APPROVED")
                else:
                    st.error(f"{v.finding_id}: REJECTED  ({', '.join(reasons)})")
                    if v.feedback:
                        st.caption(v.feedback)

    with t_rag:
        if not passages:
            st.info("No passages retrieved.")
        else:
            st.caption(f"{len(passages)} passages retrieved (top-6 with lexical rerank)")
            for p in passages:
                st.markdown(
                    f"**{p['doc']} :: {p['passage_id']}**  ·  score {p['score']:.3f}"
                )
                st.caption(p["text"][:500] + ("..." if len(p["text"]) > 500 else ""))
                st.divider()

    with t_trace:
        for t in trace:
            st.code(t)
        rc = result.get("retry_count", {})
        if rc:
            st.caption("Retry counts: " + ", ".join(f"{k}={v}" for k, v in rc.items()))

    with st.expander("Full markdown report"):
        st.markdown(result.get("final_report", "(no report)"))

    with st.expander("Raw state (debug)"):
        safe_state = {
            "trace": trace,
            "retry_count": result.get("retry_count", {}),
            "approved_ids": sorted(approved),
            "security_findings": [f.model_dump() for f in sec if hasattr(f, "model_dump")],
            "quality_findings": [f.model_dump() for f in qual if hasattr(f, "model_dump")],
        }
        st.json(safe_state)


def _safe(s: str) -> str:
    """HTML-escape a snippet for the markdown rendering."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
    )
