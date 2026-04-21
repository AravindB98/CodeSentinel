# CodeSentinel

> A multi-agent, retrieval-augmented AI system for automated code review and vulnerability detection. **Same Claude Sonnet model, same prompts, different architecture: 97% reduction in hallucinated findings.**

[![Project Website](https://img.shields.io/badge/website-github%20pages-d97706?style=flat-square&logo=github)](https://aravindb98.github.io/CodeSentinel/#source)
[![Live Demo](https://img.shields.io/badge/demo-streamlit-c2410c?style=flat-square&logo=streamlit)](https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app)
[![Video Walkthrough](https://img.shields.io/badge/video-youtube%20(7%20min)-c2410c?style=flat-square&logo=youtube)](https://youtu.be/do8GvAK7tHI)
[![Technical Report](https://img.shields.io/badge/report-PDF%20(45%20pages)-d97706?style=flat-square)](./CodeSentinel_Technical_Report.pdf)
[![Tests](https://img.shields.io/badge/tests-35%2F35%20passing-5a7a1a?style=flat-square)](./tests/)
[![License](https://img.shields.io/badge/license-MIT-grey?style=flat-square)](./LICENSE)

**Author:** Aravind Balaji · M.S. Information Systems · Northeastern University
**Course:** INFO 7375 (Prompt Engineering and Generative AI) · Spring 2026 · Prof. Nik Bear Brown
**Contact:** balaji.ara@northeastern.edu · NUID: 001564773

---

## Links

| Artifact | URL |
|---|---|
| 🌐 **Project website** | https://aravindb98.github.io/CodeSentinel/#source |
| 🧪 **Live Streamlit demo** | https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app |
| 🎬 **Video walkthrough (7 min)** | https://youtu.be/do8GvAK7tHI |
| 📦 **GitHub repository** | https://github.com/AravindB98/CodeSentinel |
| 📄 **Technical report** (45 pages) | [`CodeSentinel_Technical_Report.pdf`](./CodeSentinel_Technical_Report.pdf) |
| 🏛 **Architecture docs** | [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) |

---

## The headline number

| System                    | TPR   | FPR   | False positives | CWE accuracy |
|---------------------------|-------|-------|-----------------|--------------|
| Single-prompt baseline    | 1.000 | 0.789 | **30**          | 1.000        |
| Multi-agent CodeSentinel  | 1.000 | 0.111 | **1**           | 1.000        |
| **Δ (multi − baseline)**  | 0.000 | **−0.678** | **−29 (−97%)** | 0.000      |

Measured on April 20, 2026 with real Claude Sonnet against a 10-sample hand-labeled toy suite. Same model, same prompts to the LLM, same samples — the 97% reduction is attributable purely to the architecture. See §10.4.1 of the technical report for raw results at `eval/results/20260420_143220/`.

Paired-suite (20 samples, OWASP-Benchmark-style): **McNemar's exact p = 0.0312** (significant at α = 0.05). Youden index: +0.818 multi-agent vs −0.238 baseline.

---

## How to run it

### Quick start (no API key — mock mode)

```bash
git clone https://github.com/AravindB98/CodeSentinel.git
cd CodeSentinel
pip install -r requirements.txt
make ingest           # build ChromaDB from rag/data/
make benchmark        # deterministic mock-mode benchmark
make test             # all 35 unit tests
```

### Real LLM (requires Anthropic API key)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
unset CODESENTINEL_MOCK_LLM
make benchmark        # runs against Claude Sonnet, ~$2 for full toy suite
```

### Streamlit UI (local)

```bash
streamlit run app/streamlit_app.py
# or visit the live deployment:
# https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app
```

---

## Architecture

Three specialized agents orchestrated via LangGraph with a bounded retry loop and a hard circuit breaker.

```mermaid
flowchart LR
    IN([Source code]) --> SS[Security Sentinel<br/>RAG-grounded]
    IN --> QA[Quality Auditor<br/>style · maintainability]
    RAG[(RAG index<br/>56 passages:<br/>OWASP + CWE + patterns)] <--> SS
    SS --> EG{Evaluator Guardian<br/>programmatic + LLM}
    QA --> EG
    EG -- APPROVED --> OUT([Final Report])
    EG -. REJECTED · retry max 3 .-> SS

    style SS fill:#fff4e3,stroke:#d97706,stroke-width:2px,color:#1a1c17
    style QA fill:#fff4e3,stroke:#d97706,stroke-width:2px,color:#1a1c17
    style EG fill:#feeadc,stroke:#c2410c,stroke-width:2px,color:#1a1c17
    style RAG fill:#f0efe8,stroke:#9a9687,color:#5a584d
    style OUT fill:#f0f4e6,stroke:#5a7a1a,stroke-width:2px,color:#1a1c17
```

- **Security Sentinel** — RAG-grounded vulnerability detection. Every finding must cite a retrieved passage.
- **Code Quality Auditor** — style and maintainability review. Capped at 10 findings per file.
- **Evaluator Guardian** — adversarial reviewer. **This is the 97%.** Two-layer validation:
  - *Layer 1 (programmatic):* citation present? citation in retrieved context? fix length ≥ 20 chars? confidence ≥ 0.5? schema valid?
  - *Layer 2 (LLM semantic):* does the cited passage actually support the claim?

Every structural property — citation enforcement, retry bounds, circuit breaker, Evaluator verdicts — is preserved in **deterministic mock mode**, so anyone can reproduce the pipeline behavior without API credits.

---

## Repository structure

```
CodeSentinel/
├── .github/workflows/
│   └── deploy.yml                        # GitHub Pages deployment workflow
├── app/
│   └── streamlit_app.py                  # Live demo UI (also deployed on Streamlit Cloud)
├── graph/                                # LangGraph orchestration
│   ├── state.py                          #   shared TypedDict state
│   ├── schemas.py                        #   Pydantic + dataclass fallback
│   ├── build_graph.py                    #   LangGraph wiring + fallback runner
│   ├── agents/
│   │   ├── security_sentinel.py
│   │   ├── code_quality_auditor.py
│   │   └── evaluator_guardian.py
│   └── prompts/
│       ├── security.md                   #   versioned system prompts
│       ├── quality.md
│       └── evaluator.md
├── rag/                                  # Retrieval pipeline
│   ├── ingest.py                         #   triple-backend ingest (ChromaDB → TF-IDF → pure Python)
│   ├── retriever.py                      #   two-pass retrieval with lexical rerank
│   └── data/
│       ├── owasp_top10_2025.txt          #   10 OWASP Top 10 2025 entries
│       ├── cwe_subset.csv                #   29 CWE taxonomy entries
│       └── patterns.md                   #   17 language-specific patterns
├── synth/                                # Synthetic data generation (15 CWE templates)
│   ├── generate.py
│   ├── verify.py                         #   independent regex-based verifier
│   └── templates/
├── rl/                                   # RL modules (NOT wired into graph)
│   ├── bandit.py                         #   UCB-1 contextual bandit
│   └── policy.py                         #   REINFORCE policy gradient
├── eval/                                 # Benchmark harness
│   ├── baseline_single_prompt.py
│   ├── run_benchmark.py
│   ├── semgrep_compare.py
│   ├── datasets/
│   │   ├── toy_suite.json                #   10 hand-labeled samples
│   │   ├── paired_suite.json             #   20 OWASP-Benchmark-style
│   │   └── synthetic_suite.json          #   29 verified synthetic
│   └── results/
│       ├── 20260420_143220/              #   Real Claude Sonnet run · April 20, 2026
│       ├── toy_suite_10sample/           #   Mock-mode benchmark output
│       ├── paired_suite_20sample/        #   Mock-mode paired output
│       └── semgrep_comparison/           #   Semgrep vs CodeSentinel (Flask source)
├── utils/
│   └── llm_client.py                     # Anthropic SDK + deterministic mock
├── tests/                                # 35 unit tests (pytest-optional)
│   ├── test_rag.py
│   ├── test_agents.py
│   └── test_pipeline.py
├── website/
│   └── index.html                        # Project showcase page (deployed via Pages)
├── docs/
│   └── ARCHITECTURE.md                   # Engineering architecture doc
├── CodeSentinel_Technical_Report.pdf     # 45-page technical report
├── requirements.txt
├── Makefile
├── .env.example
├── .gitignore
├── LICENSE
└── README.md                             # (this file)
```

---

## Technology stack

| Component              | Technology                                                  |
|------------------------|-------------------------------------------------------------|
| Agent orchestration    | LangGraph with hand-rolled fallback runner                  |
| Reasoning LLM          | Anthropic Claude Sonnet via official SDK + deterministic mock |
| Embeddings             | HuggingFace all-MiniLM-L6-v2 · local CPU · 384-dim          |
| Vector store           | ChromaDB persistent with TF-IDF fallback (triple-tier)      |
| User interface         | Streamlit (paste / upload, tabs for findings / evaluator / RAG / trace) |
| Schemas                | Pydantic 2 with dataclass-based fallback                    |
| RL                     | NumPy-only (torch optional but unused)                      |
| Testing                | 35 unit tests · unittest-compatible · pytest-optional       |
| Deployment             | Streamlit Community Cloud · GitHub Pages (for `website/`)   |

---

## Honest scope disclosures

Three things this project is **not**:

1. **Not a Semgrep replacement.** Semgrep has a decade of community rule development and runs in 10 seconds per scan at zero API cost. CodeSentinel runs in minutes and costs pennies per scan. The correct positioning is **complementary**: Semgrep for high-recall low-cost triage, CodeSentinel for lower-recall higher-context deep review with verifiable provenance.

2. **Not an RL-driven system.** The UCB-1 contextual bandit and REINFORCE policy gradient modules under `rl/` converge on synthetic reward surfaces, but they are **not wired into the production agent graph in this release**. The benchmark numbers reported here do not depend on any RL contribution. Integration is concrete Future Work (§13.1).

3. **Not a substitute for formal security review** in regulated contexts (payment systems, medical devices, defense software) where human accountability and traceable review processes are mandatory.

The 97%-false-positive-reduction claim is bounded by what was actually measured: a 10-sample hand-labeled toy suite of Python and JavaScript code, evaluated on a single day against one specific LLM backend. See §10.5, §10.9, and §12.4 of the report for confidence intervals and scope boundaries.

**Cost disclosure (§11.7).** The live Streamlit demo runs against a personal Anthropic Console account funded by a personal credit card. The per-call meter continues to run for every visitor. Each demo invocation costs roughly $0.02–0.05. Mock mode is the zero-cost reproducibility path.

---

## Reproducing the results

### Mock mode (deterministic, no API key, runs in under a second)

```bash
export CODESENTINEL_MOCK_LLM=1
python -m eval.run_benchmark
# outputs: eval/results/<timestamp>/summary.md
```

### Real Claude Sonnet mode (~$2 for toy suite)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
unset CODESENTINEL_MOCK_LLM
python -m eval.run_benchmark
```

### Semgrep comparison

```bash
pip install semgrep
python -m eval.semgrep_compare --target path/to/repo
```

---

## What changed in v2 (April 21, 2026)

<details>
<summary>Click to expand v2 changelog</summary>

- **Real Claude Sonnet benchmark results** (April 20, 2026) — the 30→1 false-positive result, integrated into §10.4.1 of the report with raw data committed under `eval/results/20260420_143220/`.
- **Semgrep comparison executed** (April 20, 2026) — `eval/semgrep_compare.py` run against Flask production source; both tools returned 0 findings on clean code, establishing no-over-trigger. Documented in §10.10.
- **Paired-suite evaluation** (20 samples, OWASP-Benchmark-style) with McNemar's exact test, Wilson intervals, Youden index, and explicit power analysis in §10.7–§10.9.
- **Live Streamlit deployment** on Streamlit Community Cloud against real Claude Sonnet.
- **7-minute video walkthrough** published on YouTube.
- **GitHub Pages site** deployed via `.github/workflows/deploy.yml`.
- **45-page technical report** with 5 embedded diagrams, numbered references, warm-orange + sindoor palette.
- **16 callout boxes** explaining OWASP Top 10, CWE, LangGraph vs CrewAI vs AutoGen, RAG, SAST, system prompts, embeddings, two-pass retrieval, McNemar's test, Youden index, UCB-1, REINFORCE.
- **§11.7 cost disclosure** and **greatly expanded §13 Future Work** covering a five-plus-agent production architecture, Claude Mythos / Project Glasswing positioning, a 12-to-18-month research program, and a concrete startup commercialization path.

</details>

---

## License

MIT. See [LICENSE](./LICENSE).

## Acknowledgments

Developed under the supervision of **Prof. Nik Bear Brown** at Northeastern University. The architectural pattern (specialize · ground · adversarially validate) mirrors the approach Anthropic's Project Glasswing applies at industrial scale; the contribution of this project is demonstrating that the pattern is reproducible, testable, and teachable with open tools at the scale of an academic course project.
