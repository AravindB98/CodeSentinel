"""
RAG retriever with two-pass ranking.

Pass 1: semantic (or TF-IDF) similarity retrieves top-K candidates.
Pass 2: lexical re-ranking boosts passages whose title contains terms
        matching the query's apparent operation or vulnerability class.

This two-pass approach fixes a real failure mode where generic OWASP
entries were ranked higher than specific CWE entries for specific queries.
"""
from __future__ import annotations

import json
import logging
import math
import pickle
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

STORE_DIR = Path(__file__).resolve().parent / "chroma_store"
INDEX_PKL = Path(__file__).resolve().parent / "tfidf_index.pkl"
INDEX_JSON = Path(__file__).resolve().parent / "tfidf_index.json"


# --- Keyword boost terms for second-pass rerank ---
# Maps query-language cues to preferred passage title terms.
RERANK_KEYWORDS = {
    "sql": ["sql", "cwe-89", "injection"],
    "pickle": ["pickle", "deserial", "cwe-502"],
    "eval": ["eval", "code injection", "cwe-94"],
    "exec": ["exec", "command", "cwe-78"],
    "subprocess": ["command", "cwe-78"],
    "shell": ["command", "cwe-78"],
    "innerhtml": ["xss", "cwe-79"],
    "verify=false": ["certificate", "cwe-295"],
    "hardcoded": ["hard-coded", "cwe-798"],
    "password": ["hard-coded", "cwe-798"],
    "md5": ["broken", "cwe-327"],
    "sha1": ["broken", "cwe-327"],
    "pickle.loads": ["pickle", "deserial", "cwe-502"],
    "yaml.load": ["yaml", "deserial", "cwe-502"],
    "object.assign": ["prototype", "cwe-915"],
    "runtime.exec": ["command", "cwe-78"],
    "preparedstatement": ["sql", "cwe-89"],
    "objectinputstream": ["deserial", "cwe-502"],
    "documentbuilderfactory": ["xxe", "cwe-611"],
}


class RetrievedPassage:
    """Lightweight dataclass-ish result container."""
    def __init__(self, doc: str, passage_id: str, text: str, score: float, title: str = ""):
        self.doc = doc
        self.passage_id = passage_id
        self.text = text
        self.score = score
        self.title = title

    def as_dict(self) -> Dict:
        return {
            "doc": self.doc,
            "passage_id": self.passage_id,
            "text": self.text,
            "score": self.score,
            "title": self.title,
        }


class Retriever:
    """Unified interface over ChromaDB and TF-IDF backends."""

    def __init__(self) -> None:
        self.backend: Optional[str] = None
        self._chroma_col = None
        self._sklearn_bundle = None
        self._pure_bundle = None
        self._load()

    def _load(self) -> None:
        """Load the best available backend."""
        # Try ChromaDB first
        if STORE_DIR.exists():
            try:
                import chromadb
                client = chromadb.PersistentClient(path=str(STORE_DIR))
                self._chroma_col = client.get_collection("codesentinel")
                self.backend = "chroma"
                logger.info("Retriever backend: ChromaDB")
                return
            except Exception as e:
                logger.warning("Could not load ChromaDB: %s", e)

        # sklearn TF-IDF
        if INDEX_PKL.exists():
            try:
                with INDEX_PKL.open("rb") as f:
                    self._sklearn_bundle = pickle.load(f)
                self.backend = "sklearn_tfidf"
                logger.info("Retriever backend: sklearn TF-IDF")
                return
            except Exception as e:
                logger.warning("Could not load sklearn TF-IDF: %s", e)

        # Pure-python TF-IDF
        if INDEX_JSON.exists():
            try:
                self._pure_bundle = json.loads(INDEX_JSON.read_text(encoding="utf-8"))
                self.backend = "pure_tfidf"
                logger.info("Retriever backend: pure-python TF-IDF")
                return
            except Exception as e:
                logger.warning("Could not load pure-python TF-IDF: %s", e)

        raise RuntimeError(
            "No retrieval index found. Run `python -m rag.ingest` first."
        )

    # ---- Backend-specific retrieval ----
    def _retrieve_chroma(self, query: str, k: int) -> List[RetrievedPassage]:
        result = self._chroma_col.query(query_texts=[query], n_results=k)
        out = []
        for i in range(len(result["ids"][0])):
            meta = result["metadatas"][0][i]
            distance = result["distances"][0][i] if result.get("distances") else 0.0
            out.append(RetrievedPassage(
                doc=meta.get("doc", ""),
                passage_id=meta.get("passage_id", ""),
                text=result["documents"][0][i],
                score=max(0.0, 1.0 - float(distance)),  # distance -> similarity
                title=meta.get("title", ""),
            ))
        return out

    def _retrieve_sklearn(self, query: str, k: int) -> List[RetrievedPassage]:
        b = self._sklearn_bundle
        from sklearn.metrics.pairwise import cosine_similarity
        q_vec = b["vectorizer"].transform([query])
        sims = cosine_similarity(q_vec, b["matrix"]).flatten()
        top_idx = sims.argsort()[::-1][:k]
        out = []
        for i in top_idx:
            p = b["passages"][int(i)]
            out.append(RetrievedPassage(
                doc=p["doc"],
                passage_id=p["passage_id"],
                text=p["text"],
                score=float(sims[i]),
                title=p.get("title", ""),
            ))
        return out

    def _retrieve_pure(self, query: str, k: int) -> List[RetrievedPassage]:
        b = self._pure_bundle
        idf = b["idf"]
        tokens = re.findall(r"[a-z]+", query.lower())
        tf = Counter(tokens)
        total = sum(tf.values()) or 1
        q_vec = {w: (c / total) * idf.get(w, 0) for w, c in tf.items()}
        norm_q = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        q_vec = {w: v / norm_q for w, v in q_vec.items()}

        scored = []
        for i, d_vec in enumerate(b["vectors"]):
            keys = set(q_vec) & set(d_vec)
            score = sum(q_vec[w] * d_vec[w] for w in keys)
            scored.append((score, i))
        scored.sort(reverse=True)

        out = []
        for score, i in scored[:k]:
            p = b["passages"][i]
            out.append(RetrievedPassage(
                doc=p["doc"],
                passage_id=p["passage_id"],
                text=p["text"],
                score=float(score),
                title=p.get("title", ""),
            ))
        return out

    # ---- Public API ----
    def retrieve(
        self,
        query: str,
        k: int = 8,
        rerank: bool = True,
    ) -> List[RetrievedPassage]:
        """
        Retrieve top-k passages with optional lexical rerank.

        The rerank pass is what makes specific entries beat generic ones.
        """
        if self.backend == "chroma":
            candidates = self._retrieve_chroma(query, k * 2)
        elif self.backend == "sklearn_tfidf":
            candidates = self._retrieve_sklearn(query, k * 2)
        elif self.backend == "pure_tfidf":
            candidates = self._retrieve_pure(query, k * 2)
        else:
            return []

        if rerank:
            candidates = self._lexical_rerank(query, candidates)

        # Dedup by (doc, passage_id)
        seen = set()
        out: List[RetrievedPassage] = []
        for c in candidates:
            key = (c.doc, c.passage_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
            if len(out) >= k:
                break
        return out

    def _lexical_rerank(
        self, query: str, candidates: List[RetrievedPassage]
    ) -> List[RetrievedPassage]:
        """
        Boost candidates whose title contains rerank-keyword terms triggered
        by the query content. Boost is additive (0.0 to ~0.4) to preserve
        semantic signal but lift specific matches above generic ones.
        """
        q_lower = query.lower()
        triggered: List[str] = []
        for cue, boost_terms in RERANK_KEYWORDS.items():
            if cue in q_lower:
                triggered.extend(boost_terms)

        if not triggered:
            return candidates

        def boost(c: RetrievedPassage) -> float:
            title_lower = (c.title + " " + c.text[:300]).lower()
            hit = sum(1 for t in triggered if t in title_lower)
            return min(0.4, 0.1 * hit)

        boosted = [(c.score + boost(c), c) for c in candidates]
        boosted.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in boosted]


# Convenience singleton
_retriever: Optional[Retriever] = None


def get_retriever() -> Retriever:
    global _retriever
    if _retriever is None:
        _retriever = Retriever()
    return _retriever
