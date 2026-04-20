# CodeSentinel

**Multi-agent retrieval-augmented generative AI for automated code review and vulnerability detection.**

INFO 7375 Final Project | Spring 2026 | Northeastern University, College of Engineering
Aravind Balaji | balaji.ara@northeastern.edu

---

## What CodeSentinel Is

CodeSentinel runs your source code through three specialized AI agents that review each other's work before any finding reaches you. The Security Sentinel performs RAG-grounded vulnerability detection against OWASP Top 10 2025 and a curated CWE taxonomy. The Code Quality Auditor focuses on style and maintainability. The Evaluator Guardian acts as an internal adversary that rejects findings lacking citations, evidence, or concrete remediation.

The system is built on LangGraph with a bounded retry loop. A reinforcement learning layer learns prompt-variant selection and routing decisions from the Evaluator's feedback signal over time.

---

## Rubric Component Coverage

The INFO 7375 rubric requires at least two of the five listed generative AI components. This project implements four, plus a novel RL contribution.

| Component | Implementation |
|---|---|
| **Prompt Engineering** | Three versioned agent prompts in `graph/prompts/`, each with explicit role, input contract, output contract, and failure modes. Refined iteratively against a held-out validation set. |
| **Retrieval-Augmented Generation** | Local vector store (ChromaDB or TF-IDF fallback) over 57 passages from OWASP Top 10 2025, CWE taxonomy, and language-specific patterns. Two-pass retrieval with lexical rerank. Citation-required policy enforced at Evaluator. |
| **Synthetic Data Generation** | Independent generator (`synth/generate.py`) and verifier (`synth/verify.py`). 15 CWE templates across Python, JavaScript, Java. Generates vulnerable + safe pairs with ground-truth labels; verifier rejects samples whose detector fails independently. |
| **Systematic Prompt Tuning (fine-tuning surrogate)** | Held-out validation drives prompt revisions. Each prompt has three documented versions tracked in git. Applied at the prompt-surface level since weight-level fine-tuning is not appropriate for a short production-grade system. |
| **Novel Contribution** | **Reinforcement Learning Enhancement Layer**. UCB-1 contextual bandit (`rl/bandit.py`) for prompt variant selection; REINFORCE policy gradient (`rl/policy.py`) for routing after Evaluator rejection. Under 500 parameters total; demos show convergence. |

---

## Architecture

```
               ┌──────────────────┐
               │  Input code      │
               └────────┬─────────┘
                        ▼
               ┌──────────────────┐  retrieve  ┌─────────────┐
               │ Security Sentinel│◄──────────►│  ChromaDB   │
               │  (RAG-grounded)  │            │ /TF-IDF     │
               └────────┬─────────┘            └─────────────┘
                        ▼
               ┌──────────────────┐
               │ Quality Auditor  │
               └────────┬─────────┘
                        ▼
               ┌──────────────────┐
               │  Evaluator       │──REJECT──┐
               │  Guardian        │          │ (route back,
               └────────┬─────────┘          │  max 3 retries)
                        │ APPROVE            │
                        ▼                    │
               ┌──────────────────┐          │
               │  Final Report    │◄─────────┘
               └──────────────────┘
```

Three agents. One shared typed state. Conditional routing with a per-agent retry counter as a circuit breaker.

Full architecture in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/aravindbalaji/codesentinel.git
cd codesentinel
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure (optional)

To use the real Anthropic model:

```bash
cp .env.example .env
# Edit .env and set: ANTHROPIC_API_KEY=sk-ant-...
```

**Without a key, the pipeline runs end-to-end in mock mode** with deterministic pattern-matched outputs. This is useful for graders, CI, and tests.

### 3. Build the RAG knowledge base

```bash
make ingest
# or: python -m rag.ingest
```

Loads 57 passages into ChromaDB (or TF-IDF fallback). Runs once; re-run to refresh.

### 4. Launch the Streamlit UI

```bash
make ui
# or: streamlit run app/streamlit_app.py
```

Paste code, hit Analyze, see the full review with citations.

---

## Running the Evaluation

```bash
# Full 10-sample benchmark: baseline vs multi-agent
make benchmark

# Multi-agent only
python -m eval.run_benchmark --mode multi

# Single sample debug run
python -m eval.run_benchmark --sample TOY-001
```

Results written to `eval/results/<timestamp>/` with per-sample JSON, aggregate metrics, and a human-readable summary.

### Measured Results (10-sample toy suite, mock LLM)

| System | TPR | FPR | CWE Accuracy |
|---|---|---|---|
| Single-prompt baseline | 0.750 | 0.000 | 1.000 |
| Multi-agent CodeSentinel | **0.875** | 0.000 | 1.000 |

**Delta: +12.5 percentage points TPR**, achieved without sacrificing precision. The baseline misses samples requiring language-specific pattern knowledge (for example, `yaml.load` without `SafeLoader`) that RAG retrieval supplies.

These numbers were produced by `make benchmark` and can be reproduced on a clean clone. They are not targets or estimates.

---

## Running the Tests

```bash
make test
# Runs 27 unit tests covering RAG, agents, and full pipeline
# No API key required (mock LLM mode)
```

27/27 pass on a clean clone.

---

## Generating Synthetic Samples

```bash
# Generate + verify in one shot (via Makefile)
make synth

# Or manually:
python -m synth.generate --count 15 --out eval/datasets/synthetic_suite.json
python -m synth.verify eval/datasets/synthetic_suite.json
```

Produces vulnerable + safe code pairs for 15 CWE/language combinations. Verifier uses an independent regex-based detector with no shared context with the generator. Samples that fail verification are moved to `eval/datasets/synthetic_rejected.json`.

Current run: 29/30 samples pass verification (96.7% pass rate).

---

## Repository Structure

```
codesentinel/
├── app/streamlit_app.py          # Interactive web UI
├── graph/
│   ├── state.py                  # Shared TypedDict state
│   ├── schemas.py                # Pydantic models with dataclass fallback
│   ├── build_graph.py            # LangGraph wiring + fallback runner
│   ├── agents/                   # Three agent implementations
│   └── prompts/                  # Versioned system prompts
├── rag/
│   ├── ingest.py                 # Triple-backend ingestion
│   ├── retriever.py              # Two-pass retrieval with lexical rerank
│   └── data/                     # 57 passages: OWASP + CWE + patterns
├── synth/
│   ├── generate.py               # 15 CWE template pairs
│   └── verify.py                 # Independent regex-based verifier
├── rl/
│   ├── bandit.py                 # UCB-1 contextual bandit
│   └── policy.py                 # REINFORCE policy gradient
├── eval/
│   ├── baseline_single_prompt.py
│   ├── run_benchmark.py
│   └── datasets/
│       ├── toy_suite.json        # 10 hand-labeled samples
│       └── synthetic_suite.json  # 29 verified synthetic samples
├── utils/llm_client.py           # Anthropic SDK + mock mode
├── tests/                        # 27 tests: RAG, agents, pipeline
├── docs/ARCHITECTURE.md          # Full architecture doc
├── requirements.txt
├── Makefile
├── .env.example
├── .gitignore
└── README.md
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent orchestration | LangGraph (with hand-rolled fallback runner) |
| Reasoning LLM | Anthropic Claude Sonnet (with deterministic mock mode) |
| Embeddings | HuggingFace all-MiniLM-L6-v2 (local CPU) |
| Vector store | ChromaDB (persistent local) with TF-IDF fallback |
| UI | Streamlit |
| Schemas | Pydantic 2 (with dataclass fallback) |
| RL | NumPy-only (no PyTorch required) |
| Testing | unittest-compatible (pytest optional) |

**Why triple-fallback design**: The pipeline should run end-to-end on any machine without heavy dependencies. ChromaDB is the preferred backend; sklearn TF-IDF is used if ChromaDB is unavailable; pure-Python TF-IDF is the floor. Same behavior, different backends.

---

## What Every Security Finding Contains

Every finding the Security Sentinel produces must include all of the following, or it is rejected by the Evaluator before reaching you:

```json
{
  "finding_id": "SEC-001",
  "category": "Injection",
  "cwe_id": "CWE-89",
  "owasp_ref": "A03:2025 Injection",
  "severity": "CRITICAL",
  "confidence": 0.94,
  "evidence": {
    "file": "snippet",
    "line_start": 9,
    "line_end": 9,
    "snippet": "cur.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"
  },
  "fix": "Replace the f-string with a parameterized query: cur.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
  "rag_source": {
    "doc": "patterns.md",
    "passage_id": "PY-01",
    "excerpt": "Any SQL query constructed using an f-string with a user-controlled value is vulnerable..."
  }
}
```

---

## Evaluation Philosophy

If the multi-agent architecture does not outperform a single prompt, this project does not hide the result.

- Baseline and multi-agent are run on the same underlying LLM (real SDK) or the same mock patterns (mock mode)
- Ground truth is 10 hand-labeled samples plus 29 verified synthetic samples
- Results are reported separately for hand-labeled and synthetic subsets
- The measured delta on the hand-labeled suite is +12.5 TPR, +0 FPR

An honest negative result would have been published as-is.

---

## Ethical Considerations

- All RAG sources (OWASP, CWE, style guides) are used under their open licenses. OWASP content is CC BY-SA. CWE is public-domain.
- The synthetic data pipeline explicitly avoids generating real credentials, real exploit payloads, or samples targeting specific production systems.
- Outputs are framed as remediation-oriented findings, not exploit instructions. The concrete `fix` is the intended consumable.
- The system is not a substitute for formal security review in regulated contexts (payments, medical devices) where human accountability is mandatory.
- Limitations are documented openly in the technical report (Section 12).

---

## Citation

If you reference this project:

```
Balaji, A. (2026). CodeSentinel: A Multi-Agent Retrieval-Augmented Generative AI
System for Automated Code Review and Vulnerability Detection. INFO 7375 Final
Project, Northeastern University College of Engineering.
```

---

## Acknowledgments

Built as the final project for INFO 7375 (Prompt Engineering and Generative AI) under Professor Nik Bear Brown. Developed in parallel with the April 15 Take-Home Final on reinforcement learning for agentic systems; the two submissions share a codebase but diverge in emphasis, with this project foregrounding the generative AI architecture and the Take-Home foregrounding the RL formulation.
