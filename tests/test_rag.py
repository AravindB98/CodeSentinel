"""Tests for the RAG retrieval layer."""
from __future__ import annotations

from rag.retriever import get_retriever


def test_retriever_loads():
    r = get_retriever()
    assert r.backend in ("chroma", "sklearn_tfidf", "pure_tfidf")


def test_retrieve_returns_results():
    r = get_retriever()
    passages = r.retrieve("SQL injection via f-string", k=5)
    assert len(passages) > 0
    assert all(p.doc for p in passages)
    assert all(p.passage_id for p in passages)


def test_sql_injection_query_surfaces_py01():
    """The SQL f-string query should surface the Python-specific pattern, not the generic OWASP entry."""
    r = get_retriever()
    passages = r.retrieve("cursor.execute f-string SQL user_id injection", k=5)
    ids = [(p.doc, p.passage_id) for p in passages]
    assert ("patterns.md", "PY-01") in ids, f"expected PY-01 in top-5; got {ids}"


def test_pickle_query_surfaces_cwe502_and_py02():
    r = get_retriever()
    passages = r.retrieve("pickle.loads deserialization untrusted", k=5)
    ids = {(p.doc, p.passage_id) for p in passages}
    assert ("cwe_subset.csv", "CWE-502") in ids
    assert ("patterns.md", "PY-02") in ids


def test_subprocess_query_surfaces_cwe78():
    r = get_retriever()
    passages = r.retrieve("subprocess shell=True user input", k=5)
    ids = {(p.doc, p.passage_id) for p in passages}
    assert ("patterns.md", "PY-03") in ids
    assert ("cwe_subset.csv", "CWE-78") in ids


def test_rerank_boosts_specific_over_generic():
    """With the two-pass rerank, PY-01 should rank above generic A03 entry for a specific query."""
    r = get_retriever()
    passages = r.retrieve("cursor.execute f-string SQL injection", k=10)
    py01_rank = next((i for i, p in enumerate(passages) if p.passage_id == "PY-01"), None)
    a03_rank = next((i for i, p in enumerate(passages) if p.passage_id == "A03-01"), None)
    assert py01_rank is not None
    if a03_rank is not None:
        assert py01_rank < a03_rank, "specific PY-01 should outrank generic A03-01"


def test_empty_query_handled():
    r = get_retriever()
    passages = r.retrieve("", k=3)
    # Should not raise, even if the scores are low
    assert isinstance(passages, list)
