# CodeSentinel

> A multi-agent, retrieval-augmented AI system for automated code review and vulnerability detection. **Same Claude Sonnet model, same prompts, different architecture: 97% reduction in hallucinated findings.**

[![Live Demo](https://img.shields.io/badge/demo-streamlit-d97706?style=flat-square&logo=streamlit)](https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app)
[![Report](https://img.shields.io/badge/report-PDF%20(45%20pages)-c2410c?style=flat-square)](./CodeSentinel_Technical_Report.pdf)
[![Tests](https://img.shields.io/badge/tests-35%2F35%20passing-5a7a1a?style=flat-square)](./tests/)
[![License](https://img.shields.io/badge/license-MIT-grey?style=flat-square)](./LICENSE)

**Author:** Aravind Balaji · M.S. Information Systems · Northeastern University
**Course:** INFO 7375 (Prompt Engineering and Generative AI) · Spring 2026 · Prof. Nik Bear Brown
**Contact:** balaji.ara@northeastern.edu · NUID: 001564773

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

### Quick start (no API key needed — mock mode)

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

### Streamlit UI

```bash
streamlit run app/streamlit_app.py
# or visit the live deployment:
# https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app
```

---

## Architecture

Three specialized agents orchestrated via LangGraph with a bounded retry loop and a hard circuit breaker.

```
                        ┌──── RAG index (56 passages) ────┐
                        │     OWASP + CWE + patterns       │
                        └──────────────┬──────────────────┘
                                       │
                                       ▼
Source code ─► Security Sentinel ─┐
               (RAG-grounded)     │
               ─► Quality Auditor ─┤─► Evaluator Guardian ─APPROVED─► Final Report
                  (style/maint.)   │   (programmatic + LLM)
                                   │           │
                                   │    REJECTED · retry (max 3)
                                   └◄──────────┘
```

- **Security Sentinel** — RAG-grounded vulnerability detection. Every finding must cite a retrieved passage.
- **Code Quality Auditor** — style and maintainability review. Capped at 10 findings per file.
- **Evaluator Guardian** — adversarial reviewer. **This is the 97%.** Two-layer validation:
  - *Layer 1 (programmatic):* citation present? citation in retrieved context? fix length ≥ 20 chars? confidence ≥ 0.5? schema valid?
  - *Layer 2 (LLM semantic):* does the cited passage actually support the claim?

Every structural property — citation enforcement, retry bounds, circuit breaker, Evaluator verdicts — is preserved in **deterministic mock mode**, so anyone can reproduce the pipeline behavior without API credits.

---

## What's in this repository

```
codesentinel/
├── app/streamlit_app.py              # Live demo UI
├── graph/                            # LangGraph orchestration
│   ├── state.py, schemas.py, build_graph.py
│   ├── agents/ (sentinel, auditor, evaluator)
│   └── prompts/ (system prompts, versioned)
├── rag/                              # Retrieval pipeline
│   ├── ingest.py, retriever.py
│   └── data/ (owasp.md, cwe_subset.csv, patterns.md)
├── synth/                            # Synthetic data (15 CWE templates)
│   ├── generate.py, verify.py (independent regex verifier)
│   └── templates/
├── rl/                               # RL modules (not wired into graph)
│   ├── bandit.py (UCB-1)
│   └── policy.py (REINFORCE)
├── eval/                             # Benchmark harness
│   ├── baseline.py, run_benchmark.py
│   ├── semgrep_compare.py            # Semgrep comparison harness
│   ├── datasets/ (toy + paired + synth)
│   └── results/20260420_143220/      # Real Claude Sonnet run, April 20
├── tests/                            # 35 unit tests, pytest-optional
├── docs/ARCHITECTURE.md
├── CodeSentinel_Technical_Report.pdf # 45-page technical report
├── requirements.txt, Makefile, .env.example
└── README.md
```

---

## Technology stack

| Component              | Technology                                                  |
|------------------------|-------------------------------------------------------------|
| Agent orchestration    | LangGraph with hand-rolled fallback runner                  |
| Reasoning LLM          | Anthropic Claude Sonnet via official SDK + deterministic mock |
| Embeddings             | HuggingFace all-MiniLM-L6-v2 · local CPU · 384-dim          |
| Vector store           | ChromaDB persistent with TF-IDF fallback (triple-tier)      |
| User interface         | Streamlit (paste / upload input, tabs for findings / evaluator / RAG / trace) |
| Schemas                | Pydantic 2 with dataclass-based fallback                    |
| RL                     | NumPy-only (torch optional but unused)                      |
| Testing                | 35 unit tests · unittest-compatible · pytest-optional       |

---

## What changed in v2 (April 21, 2026)

Compared to the initial submission, the current release and accompanying **45-page technical report** add:

- **Real Claude Sonnet benchmark results** (April 20, 2026) — the 30→1 false-positive result, integrated into §10.4.1 of the report with raw data committed under `eval/results/20260420_143220/`.
- **Semgrep comparison executed** (April 20, 2026) — `eval/semgrep_compare.py` run against Flask production source; both tools returned 0 findings on clean code, establishing no-over-trigger. Documented in §10.10.
- **Paired-suite evaluation** (20 samples, OWASP-Benchmark-style) with McNemar's exact test, Wilson intervals, Youden index, and explicit power analysis in §10.7–§10.9.
- **Live Streamlit deployment** on Streamlit Community Cloud against real Claude Sonnet (link above).
- **5 embedded diagrams** in the technical report — three-agent architecture, LangGraph state machine, RAG pipeline, dual-panel results chart, Evaluator two-layer flow. All in a warm-orange + sindoor palette consistent with the project website.
- **Expanded concept explanations** throughout the report — 16 callout boxes defining OWASP Top 10, CWE taxonomy, LangGraph vs CrewAI vs AutoGen, RAG, SAST, system prompts, embeddings, two-pass retrieval, McNemar's test, Youden index, UCB-1, REINFORCE, and the three-agent design rationale.
- **§11.7 — Personal API Funding and Real-Time Cost Exposure.** Honest disclosure that the live demo runs against a personal credit card attached to an Anthropic Console account, and the meter continues to run for every visitor. Mock mode is the reproducibility path for anyone without credits.
- **Greatly expanded §13 Future Work** — six subsections covering near-term RL integration, a five-plus-agent production architecture, positioning as a Claude Mythos / Project Glasswing alternative at open-tool scale, a 12-to-18-month research program, and a concrete startup commercialization path with unit-economics math.
- **Numbered references** `[1]` through `[26]` and a dedicated title page with NUID, repository link, and live-demo URL.

---

## Honest scope disclosures

Three things this project is **not**:

1. **Not a Semgrep replacement.** Semgrep has a decade of community rule development and runs in 10 seconds per scan at zero API cost. CodeSentinel runs in minutes and costs pennies per scan. The correct positioning is **complementary**: Semgrep for high-recall low-cost triage, CodeSentinel for lower-recall higher-context deep review with verifiable provenance.

2. **Not an RL-driven system.** The UCB-1 contextual bandit and REINFORCE policy gradient modules under `rl/` converge on synthetic reward surfaces, but they are **not wired into the production agent graph in this release**. The benchmark numbers reported here do not depend on any RL contribution. Integration is concrete Future Work (§13.1).

3. **Not a substitute for formal security review** in regulated contexts (payment systems, medical devices, defense software) where human accountability and traceable review processes are mandatory.

The 97%-false-positive-reduction claim is bounded by what was actually measured: a 10-sample hand-labeled toy suite of Python and JavaScript code, evaluated on a single day against one specific LLM backend. See §10.5, §10.9, and §12.4 of the report for confidence intervals and scope boundaries.

---

## Reproducing the results

### Mock mode (deterministic, no API key, runs in under a second)

```bash
export CODESENTINEL_MOCK_LLM=1
python -m eval.run_benchmark
# outputs: eval/results/<timestamp>/summary.md
```

### Real Claude Sonnet mode (requires API key, ~$2 for toy suite)

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

## Links

- **Live demo:** https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app
- **Technical report:** [CodeSentinel_Technical_Report.pdf](./CodeSentinel_Technical_Report.pdf) (45 pages)
- **Architecture docs:** [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md)
- **Repository:** https://github.com/AravindB98/CodeSentinel

---

## License

MIT. See [LICENSE](./LICENSE).

## Acknowledgments

Developed under the supervision of **Prof. Nik Bear Brown** at Northeastern University. The architectural pattern (specialize · ground · adversarially validate) mirrors the approach Anthropic's Project Glasswing applies at industrial scale; the contribution of this project is demonstrating that the pattern is reproducible, testable, and teachable with open tools at the scale of an academic course project.
