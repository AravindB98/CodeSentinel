"""
RAG ingestion pipeline.

Loads the OWASP Top 10 2025, CWE taxonomy subset, and language-specific
vulnerability patterns into a retrievable index.

Primary backend: ChromaDB with sentence-transformers embeddings.
Fallback backend: in-memory TF-IDF (scikit-learn) if ChromaDB or
sentence-transformers are unavailable.

Both backends expose the same retrieval interface via rag.retriever.Retriever.

Run:
    python -m rag.ingest
"""
from __future__ import annotations

import csv
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(message)s")


DATA_DIR = Path(__file__).resolve().parent / "data"
STORE_DIR = Path(__file__).resolve().parent / "chroma_store"
INDEX_JSON = Path(__file__).resolve().parent / "tfidf_index.json"


def load_owasp(path: Path) -> List[Dict[str, str]]:
    """Load OWASP passages. Each line: PASSAGE_ID|||TITLE|||BODY (skip comments)."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        parts = line.split("|||")
        if len(parts) != 3:
            continue
        pid, title, body = parts
        out.append({
            "doc": "owasp_top10_2025.txt",
            "passage_id": pid.strip(),
            "title": title.strip(),
            "text": f"{title.strip()}. {body.strip()}",
        })
    return out


def load_cwe(path: Path) -> List[Dict[str, str]]:
    """Load CWE rows from CSV."""
    out = []
    with path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cwe_id = row["cwe_id"].strip()
            title = row["name"].strip()
            body = f"{row['description'].strip()} Fix: {row['fix_pattern'].strip()}"
            out.append({
                "doc": "cwe_subset.csv",
                "passage_id": cwe_id,
                "title": f"{cwe_id} {title}",
                "text": f"{cwe_id} {title}. {body}",
            })
    return out


def load_patterns(path: Path) -> List[Dict[str, str]]:
    """Load language-specific patterns in same format as OWASP."""
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        parts = line.split("|||")
        if len(parts) != 4:
            continue
        pid, title, lang, body = parts
        out.append({
            "doc": "patterns.md",
            "passage_id": pid.strip(),
            "title": title.strip(),
            "language": lang.strip(),
            "text": f"{title.strip()} ({lang.strip()}). {body.strip()}",
        })
    return out


def load_all() -> List[Dict[str, str]]:
    """Load all RAG corpora."""
    corpora = []
    owasp_path = DATA_DIR / "owasp_top10_2025.txt"
    cwe_path = DATA_DIR / "cwe_subset.csv"
    patterns_path = DATA_DIR / "patterns.md"

    if owasp_path.exists():
        corpora.extend(load_owasp(owasp_path))
        logger.info("Loaded %d OWASP passages", len([c for c in corpora if c["doc"].startswith("owasp")]))
    if cwe_path.exists():
        corpora.extend(load_cwe(cwe_path))
    if patterns_path.exists():
        corpora.extend(load_patterns(patterns_path))
    logger.info("Total passages: %d", len(corpora))
    return corpora


def ingest_chroma(passages: List[Dict[str, str]]) -> bool:
    """Try to ingest into ChromaDB. Returns True on success."""
    try:
        import chromadb
        from chromadb.utils import embedding_functions
    except ImportError:
        logger.warning("chromadb not installed; falling back to TF-IDF")
        return False

    try:
        STORE_DIR.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(STORE_DIR))

        # Try sentence-transformers for real embeddings
        try:
            ef = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
        except Exception as e:
            logger.warning("sentence-transformers unavailable (%s); falling back to default", e)
            ef = embedding_functions.DefaultEmbeddingFunction()

        # Recreate to ensure clean state
        try:
            client.delete_collection("codesentinel")
        except Exception:
            pass

        col = client.create_collection(name="codesentinel", embedding_function=ef)
        ids = [f"{p['doc']}::{p['passage_id']}" for p in passages]
        docs = [p["text"] for p in passages]
        metas = [{"doc": p["doc"], "passage_id": p["passage_id"], "title": p.get("title", "")}
                 for p in passages]
        col.add(ids=ids, documents=docs, metadatas=metas)
        logger.info("ChromaDB ingest complete: %d passages in %s", len(passages), STORE_DIR)
        return True
    except Exception as e:
        logger.warning("ChromaDB ingest failed (%s); falling back to TF-IDF", e)
        return False


def ingest_tfidf(passages: List[Dict[str, str]]) -> bool:
    """Build a TF-IDF index as a persistent JSON blob.

    Uses scikit-learn if available, else a manual TF-IDF implementation.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        import numpy as np

        docs = [p["text"] for p in passages]
        vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=5000)
        matrix = vec.fit_transform(docs)

        # Serialize
        import pickle as _pickle
        blob_path = INDEX_JSON.with_suffix(".pkl")
        with blob_path.open("wb") as f:
            _pickle.dump({
                "vectorizer": vec,
                "matrix": matrix,
                "passages": passages,
            }, f)
        logger.info("TF-IDF (sklearn) ingest complete: %d passages in %s", len(passages), blob_path)
        return True
    except ImportError:
        logger.info("sklearn not available; using pure-python TF-IDF")

    # Pure-python fallback
    from collections import Counter
    import math
    import re

    def tokenize(s: str) -> List[str]:
        return re.findall(r"[a-z]+", s.lower())

    all_tokens = [tokenize(p["text"]) for p in passages]
    df: Counter = Counter()
    for tokens in all_tokens:
        for w in set(tokens):
            df[w] += 1
    N = len(passages)
    idf = {w: math.log((N + 1) / (c + 1)) + 1 for w, c in df.items()}

    index = []
    for tokens in all_tokens:
        tf = Counter(tokens)
        total = sum(tf.values()) or 1
        vec = {w: (count / total) * idf.get(w, 0) for w, count in tf.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        vec = {w: v / norm for w, v in vec.items()}
        index.append(vec)

    payload = {
        "type": "pure_tfidf",
        "idf": idf,
        "vectors": index,
        "passages": passages,
    }
    INDEX_JSON.write_text(json.dumps(payload), encoding="utf-8")
    logger.info("Pure-python TF-IDF ingest complete: %d passages in %s", N, INDEX_JSON)
    return True


def main() -> None:
    """Entry point for `python -m rag.ingest`."""
    passages = load_all()
    if not passages:
        logger.error("No passages loaded. Check rag/data/ contents.")
        raise SystemExit(1)

    # Prefer ChromaDB; fall back to TF-IDF
    if ingest_chroma(passages):
        logger.info("Primary backend: ChromaDB ready at %s", STORE_DIR)
    else:
        ingest_tfidf(passages)
        logger.info("Fallback backend: TF-IDF ready")


if __name__ == "__main__":
    main()
