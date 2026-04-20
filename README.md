# CodeSentinel

**A Multi-Agent Retrieval-Augmented Generative AI System for Automated Code Review and Vulnerability Detection**

INFO 7375 — Prompt Engineering and Generative AI | Spring 2026
Aravind Balaji | M.S. Information Systems, Northeastern University College of Engineering
balaji.ara@northeastern.edu | [aravindbalaji.com](https://aravindbalaji.com)

---

## Table of Contents

- [What CodeSentinel Is](#what-codesentinel-is)
- [Why This Project Exists](#why-this-project-exists)
- [How It Works (Architecture)](#how-it-works-architecture)
- [Measured Results](#measured-results)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Quick Start](#quick-start)
- [Rubric Compliance With Evidence](#rubric-compliance-with-evidence)
- [Comparison With Industry Products](#comparison-with-industry-products)
- [Portfolio Piece](#portfolio-piece)
- [Honest Limitations](#honest-limitations)
- [References](#references)
- [License](#license)
- [Citation](#citation)
- [Acknowledgments](#acknowledgments)

---

## What CodeSentinel Is

CodeSentinel is a multi-agent code review system in which three specialized LLM agents — a Security Sentinel, a Code Quality Auditor, and an Evaluator Guardian — review each other's work through a LangGraph directed graph before any finding reaches the user. Every security finding must cite a passage retrieved from a local index of OWASP Top 10 2025 and CWE taxonomy entries; findings without citations are programmatically rejected. A bounded retry loop allows the Evaluator to route rejections back to upstream agents with structured feedback, with a three-retry circuit breaker to guarantee termination.

The system is built as a reproducible research artifact with a deterministic mock-LLM mode enabling the full pipeline (and all 35 unit tests) to run without an API key. A reinforcement learning demonstration module (UCB-1 contextual bandit over prompt variants, REINFORCE policy gradient over routing decisions) is included in the repository but is not integrated into the production agent graph in this release; the benchmark numbers reported below do not depend on it.

**The thesis**: when an LLM application is rearchitected into specialized, grounded, adversarially-reviewed agents, the gains come from the architecture rather than from the underlying model. Those gains should compose with any model the field produces next.

---

## Why This Project Exists

Single-prompt LLM code review has three failure modes that matter in practice, each documented with industry data:

1. **Hallucinated vulnerabilities.** Models invent plausible-sounding CWEs with no grounding. A finding citing `A03:2025` might be real, or the model might be pattern-matching on the word "database" without evidence to check against.

2. **Silent omissions.** Real defects slip past. The single-prompt baseline in the benchmark below missed `yaml.load` without `SafeLoader` (CWE-502) and `hashlib.md5` used for password hashing (CWE-327) — both textbook RCEs documented in the 2025 OWASP Top 10.

3. **Untraceable findings.** Even correct findings arrive without provenance. If a claim cannot be traced to an authoritative source, it cannot be handed to a human reviewer, an auditor, or a customer.

Prompt-tuning alone cannot fix any of these. They are architectural failures that require architectural fixes.

The problem matters because the code-review gap is widening. According to the 2025 Stack Overflow Developer Survey of 49,000+ respondents, 84% of developers now use or plan to use AI coding tools, with roughly 41% of code written in 2025 reported as AI-generated. Meanwhile, Veracode's 2025 State of Software Security scanned over a million applications and found that roughly half contain at least one OWASP Top 10 flaw. Code is being produced faster than it is reviewed. The IBM Cost of a Data Breach Report places the average breach at $4.45M USD, with textbook known-pattern vulnerabilities (Equifax's Struts patch failure, Capital One's misconfigured cloud server) responsible for the largest incidents of recent years.

CodeSentinel does not claim to solve this. It demonstrates that a specific architectural pattern — specialization, grounding, adversarial validation — produces measurable gains over single-prompt review on the same underlying model.

---

## How It Works (Architecture)

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

Three agents, one shared typed state, conditional routing with a per-agent retry counter acting as a circuit breaker.

- **Security Sentinel** — RAG-grounded vulnerability detection. Builds a retrieval query from language cues and suspicious tokens, fetches top-6 passages with two-pass semantic plus lexical rerank, and emits findings that *must* cite a retrieved passage by ID. Findings without valid citations are rejected downstream.
- **Code Quality Auditor** — Style, maintainability, and error-handling review. Explicitly non-overlapping with Security Sentinel territory; never emits CRITICAL severity. Capped at 10 findings per file to prevent alert fatigue.
- **Evaluator Guardian** — Adversarial reviewer with two layers. First a programmatic check (schema validity, citation presence in retrieved context, fix length ≥20 characters, confidence ≥0.5). Then, only if programmatic passes, an LLM semantic check for whether the cited passage actually supports the claim. Rejections produce structured feedback routed back to the upstream agent.

Full architecture and routing logic in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Measured Results

Two evaluation modes: **mock-LLM** (deterministic, reproducible on any clone with no API key) and **real-LLM** (Anthropic Claude Sonnet, run April 20 2026, ~$2 total). Both modes are reported; they tell complementary stories.

### Real-LLM Results (April 20, 2026 — `eval/results/20260420_143220/`)

**Toy suite — 10 hand-labeled samples, real Anthropic SDK**

| System | TPR | FP count | FPR | CWE accuracy |
|---|---|---|---|---|
| Single-prompt baseline | **1.000** | 30 | 0.789 | 1.000 |
| **Multi-agent CodeSentinel** | **1.000** | **1** | **0.111** | **1.000** |

Delta: **TPR ±0.000, FPR −0.678**. Both systems catch all 8 ground-truth findings. The Evaluator Guardian eliminates **29 of 30 baseline false positives** — the architecture's value with a real LLM is primarily in FPR control, not TPR. The 1 remaining multi-agent FP is on TOY-006 (a pattern-detection ambiguity; documented). McNemar: no discordant pairs on TP detection, test not applicable.

**Key insight**: With a real LLM, the single-prompt baseline detects everything *and* invents 30 false positives (3 per sample on average). The Evaluator Guardian enforces citation evidence and confidence thresholds, reducing FP output by 97%.

### Mock-LLM Results (reproducible, no API key)

**Toy suite — 10 hand-labeled samples**

| System | TPR | FPR | CWE accuracy | McNemar p |
|---|---|---|---|---|
| Single-prompt baseline | 0.750 | 0.000 | 1.000 | — |
| **Multi-agent CodeSentinel** | **1.000** | **0.000** | **1.000** | 0.5000 (n.s.) |

Delta: **+0.250 TPR**. Direction favors multi-agent; ten samples is too few for statistical significance on its own.

**Paired suite — 20 samples (10 true-positive + 10 false-positive traps), OWASP-Benchmark-style**

| System | TPR | FPR | CWE accuracy | Youden | McNemar p |
|---|---|---|---|---|---|
| Single-prompt baseline | 0.333 | 0.571 | 1.000 | −0.238 | — |
| **Multi-agent CodeSentinel** | **1.000** | **0.182** | **1.000** | **+0.818** | **0.0312** |

Delta: **+0.667 TPR, −0.389 FPR**. McNemar's exact two-sided p = 0.0312, **significant at α = 0.05**. Six discordant pairs, all favoring multi-agent.

The two multi-agent false positives on the paired suite are (1) `hashlib.md5` used as a content-addressed cache key and (2) a dead-code vulnerable branch. Both are decomposed in §10.8 of the technical report with three concrete mitigation paths.

**35/35 unit tests pass** on a clean clone in mock mode with no external dependencies.

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Agent orchestration | LangGraph 1.1.x | Explicit state transitions; `add_conditional_edges` maps cleanly to a bounded retry loop with visible routing logic |
| Reasoning LLM | Anthropic Claude Sonnet (via `anthropic` SDK) | Strong code reasoning; structured output adherence |
| Fallback LLM mode | Custom deterministic mock | Enables offline testing, CI, and evaluation without an API key |
| Embeddings | HuggingFace `all-MiniLM-L6-v2` (local CPU) | Small, fast, no external API dependency |
| Vector store | ChromaDB 0.5.x (persistent local) | Embedded, no server required |
| Fallback retrieval | scikit-learn TF-IDF | Works when ChromaDB + sentence-transformers unavailable |
| Floor retrieval | Pure-Python TF-IDF | Works with zero heavy dependencies |
| Schemas | Pydantic 2.x (with dataclass fallback) | Strict contract enforcement at agent boundaries; fallback makes the code runnable without Pydantic |
| UI | Streamlit 1.38+ | Single-file interactive UI; no frontend build step |
| RL (demonstration module only) | NumPy | No PyTorch required; keeps dependencies minimal |
| Testing | `unittest`-compatible (pytest optional) | Runs with the Python standard library; pytest not required |
| Document generation | docx-js, LibreOffice | Reproducible report PDF generation |

**The three-tier fallback design** (ChromaDB → sklearn → pure Python) means the full pipeline runs end-to-end on any machine, including graders' environments with minimal setup. This is tested: the benchmark results above were produced without ChromaDB or Pydantic installed.

---

## Repository Structure

```
codesentinel/
├── app/
│   └── streamlit_app.py                Interactive Streamlit UI
├── docs/
│   ├── ARCHITECTURE.md                 Architecture doc with ASCII diagram
│   ├── CodeSentinel_Technical_Report.pdf  23-page technical report
│   ├── CodeSentinel_Technical_Report.docx Editable source of the report
│   └── REVIEWERS_GUIDE.md              15-minute grader walkthrough
├── graph/
│   ├── state.py                        Shared TypedDict state
│   ├── schemas.py                      Pydantic models + dataclass fallback
│   ├── build_graph.py                  LangGraph wiring + hand-rolled fallback runner
│   ├── agents/
│   │   ├── security_sentinel.py        RAG-grounded vulnerability detector
│   │   ├── code_quality_auditor.py     Style + maintainability reviewer
│   │   └── evaluator_guardian.py       Adversarial validator (programmatic + LLM)
│   └── prompts/
│       ├── security.md                 Security Sentinel system prompt
│       ├── quality.md                  Quality Auditor system prompt
│       └── evaluator.md                Evaluator Guardian system prompt
├── rag/
│   ├── ingest.py                       Triple-backend RAG ingestion
│   ├── retriever.py                    Two-pass retrieval with lexical rerank
│   └── data/
│       ├── owasp_top10_2025.txt        10 OWASP category passages
│       ├── cwe_subset.csv              29 CWE taxonomy passages
│       └── patterns.md                 17 language-specific patterns
├── synth/
│   ├── generate.py                     15 CWE template pairs; vuln/safe outputs
│   └── verify.py                       Independent regex-based verifier
├── rl/                                 Demonstration modules (not wired into graph)
│   ├── bandit.py                       UCB-1 contextual bandit
│   └── policy.py                       REINFORCE policy gradient
├── eval/
│   ├── baseline_single_prompt.py       Single-prompt baseline CodeSentinel is compared against
│   ├── run_benchmark.py                Benchmark runner + McNemar's exact test
│   ├── semgrep_compare.py              Real-world comparison protocol
│   ├── datasets/
│   │   ├── toy_suite.json              10 hand-labeled samples
│   │   ├── paired_suite.json           20 samples, OWASP-Benchmark-style
│   │   ├── synthetic_suite.json        29 verified synthetic samples
│   │   └── synthetic_rejected.json     Samples the verifier rejected
│   └── results/
│       ├── toy_suite_10sample/         Committed benchmark output
│       ├── paired_suite_20sample/      Committed benchmark output
│       └── semgrep_comparison/         Semgrep vs CodeSentinel on Flask source (Apr 2026)
├── utils/
│   └── llm_client.py                   Anthropic SDK wrapper + mock-mode fallback
├── tests/                              35 tests across 4 files
│   ├── test_pipeline.py                7 end-to-end tests
│   ├── test_agents.py                  13 per-agent tests
│   ├── test_rag.py                     7 retrieval tests
│   └── test_adversarial_failures.py    8 silent-failure tests
├── index.html                          Project showcase page
├── requirements.txt                    Pinned dependencies
├── Makefile                            Targets: install, ingest, test, benchmark, etc.
├── .env.example                        Template for API-key config
├── .gitignore
├── LICENSE                             MIT License
└── README.md                           This file
```

Total: 4,600+ lines of Python across 46 files, plus documentation. Every Python file has a module-level docstring explaining purpose and contracts.

---

## Quick Start

### Prerequisites
- Python 3.11+ (tested on 3.11 and 3.12)
- ~100 MB disk space for dependencies

### Installation

```bash
git clone https://github.com/AravindB98/CodeSentinel.git
cd codesentinel
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Optional: Real LLM mode

```bash
cp .env.example .env
# Edit .env and set: ANTHROPIC_API_KEY=sk-ant-...
```

Without an API key, the pipeline runs in deterministic mock mode. All results reported in this README were measured in mock mode.

### Build the RAG index

```bash
make ingest
```

Loads 56 passages into ChromaDB, or sklearn TF-IDF, or pure-Python TF-IDF (whichever backend is available). Idempotent; safe to re-run.

### Run the tests

```bash
make test
```

Expected: **35/35 passing** in about 2 seconds.

### Run the benchmarks

```bash
make benchmark          # 10-sample toy suite
make benchmark-paired   # 20-sample OWASP-Benchmark-style paired suite
```

Results are written to `eval/results/<timestamp>/` with per-sample JSON, aggregate metrics, and a human-readable summary. The committed `toy_suite_10sample/` and `paired_suite_20sample/` directories reproduce exactly from `make benchmark`.

### Run the Streamlit UI

```bash
make ui
```

Paste code, click Analyze, see findings with RAG citations.

**Live cloud deployment**: [codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app](https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app) — deployed on Streamlit Community Cloud, branch `master`, entry point `app/streamlit_app.py`. ANTHROPIC_API_KEY injected via Streamlit Secrets.

### Real-world Semgrep comparison

```bash
pip install semgrep
make semgrep-compare FILES='path/to/file.py path/to/other.py'
```

Produces an adjudication worksheet in `eval/results/semgrep_comparison/` comparing CodeSentinel against Semgrep on the same files. Protocol specified in §10.10 of the technical report.

---

## Rubric Compliance With Evidence

The INFO 7375 assignment requires **at least 2 of the 5 listed generative AI components**. This project implements **4 of 5**, with the fifth (multimodal) being out of scope for text-based code review.

Each entry below points to specific code that demonstrates the component.

### 1. Prompt Engineering ✅

| Requirement from rubric | Evidence in this project |
|---|---|
| Design systematic prompting strategies | Three role-specialized system prompts in `graph/prompts/`: `security.md`, `quality.md`, `evaluator.md`. Each specifies role, input contract, output contract, and rejection reasons. |
| Implement context management | Shared typed state in `graph/state.py` (`CodeSentinelState` TypedDict) threads context through all agents explicitly rather than via prompt concatenation. |
| Create specialized user interaction flows | Streamlit UI in `app/streamlit_app.py` with sidebar API key config, demo snippets, and RAG status indicator. |
| Handle edge cases and errors gracefully | Every agent has try/except around LLM calls with graceful degradation; the Evaluator rejects malformed findings before surfacing. See `_parse_findings` in each agent file for schema-based rejection. |

### 2. Retrieval-Augmented Generation ✅

| Requirement from rubric | Evidence in this project |
|---|---|
| Build a knowledge base for your domain | 56 passages across three sources: OWASP Top 10 2025 (10 entries), CWE taxonomy subset (29 entries), language-specific patterns (17 entries). See `rag/data/`. |
| Implement vector storage and retrieval | `rag/retriever.py` implements a unified interface over three backends (ChromaDB, sklearn TF-IDF, pure-Python TF-IDF) with automatic fallback. |
| Design relevant document chunking strategies | Semantic-boundary chunking: one passage per OWASP category, one per CWE, one per named pattern. Documented rationale in §6.3 of the technical report. |
| Create effective ranking and filtering mechanisms | Two-pass retrieval: semantic top-2k retrieval followed by lexical rerank boosting specific CWE matches over generic OWASP entries. See `_lexical_rerank` in `rag/retriever.py`. Locked in by `test_rerank_boosts_specific_over_generic`. |

### 3. Synthetic Data Generation ✅

| Requirement from rubric | Evidence in this project |
|---|---|
| Create synthetic datasets for training or testing | `synth/generate.py`: 15 CWE template pairs spanning Python, JavaScript, Java; produces paired vulnerable and safe code samples with ground-truth labels. |
| Implement data augmentation techniques | Each template generates multiple sample variants with different variable names, function signatures, and surrounding context. |
| Ensure diversity and quality of generated data | **Independent verifier** in `synth/verify.py` uses regex-based detectors completely separate from the generator's templates and prompts. Samples failing verification are moved to `synthetic_rejected.json`. Current pass rate: 29/30 (96.7%). The one rejection is evidence the verifier is genuinely independent rather than a copy of the generator. |
| Address privacy or ethical considerations | Templates explicitly avoid real credentials, real exploit payloads, and samples targeting specific production systems. Documented in §12 of the technical report. |

### 4. Reinforcement Learning (beyond rubric) 

| Claim | Evidence and honest scope |
|---|---|
| UCB-1 contextual bandit for prompt variant selection | `rl/bandit.py`; converges to correct best-arm per context on a synthetic reward surface after ~200 rounds. |
| REINFORCE policy gradient for routing | `rl/policy.py`; recovers correct action-per-rejection-reason mapping after ~600 training steps with <500 parameters. |
| **Honest scope marker** | The RL modules are **not wired into the production agent graph** in this release. The benchmark numbers reported in this README do not depend on them. This is disclosed in the README rubric table, in the Abstract of the technical report, at the start of §8, and in the Conclusion. RL integration is an explicit Future Work item in §13. |

### 5. Multimodal Integration ❌ (out of scope)

Code review is a text-only task. Multimodal integration is not implemented. The rubric requires only two of the five components; this project implements four.

---

## Comparison With Industry Products

This is a course project, not a competitor to production SAST tools. The comparison below is honest about where CodeSentinel stands relative to the state of the art.

| Property | Semgrep | CodeQL | Snyk Code | GitHub Copilot | Bito CodeReviewAgent | **CodeSentinel** |
|---|---|---|---|---|---|---|
| **Primary technique** | Rule-based pattern matching | Dataflow + taint analysis | ML + dataflow | LLM code completion | Single-prompt LLM | **Multi-agent LLM + RAG** |
| **Vulnerability grounding** | Hand-written rules | Dataflow graphs | Trained model + rules | None (completion-only) | Implicit in prompt | **Explicit RAG citations (OWASP/CWE)** |
| **Adversarial self-review** | No | No | No | No | No | **Yes (Evaluator Guardian)** |
| **Hallucination defense** | N/A (not generative) | N/A | N/A | User-responsibility | Prompt-level only | **Programmatic + LLM validation** |
| **Provenance per finding** | Rule ID | Query ID | Model + rule reference | None | None | **RAG passage ID + CWE + OWASP ref** |
| **Run without API key** | Yes | Yes | Partial | No | No | **Yes (mock mode)** |
| **Open source** | Yes | Yes (LGTM became CodeQL) | No | No | No | **Yes (MIT)** |
| **Maturity** | 10+ years, thousands of rules | 10+ years | 8+ years | 2+ years | 2+ years | **Course project, Spring 2026** |
| **Target scale** | Production | Production | Production | IDE assistance | Team code review | **Research demonstration** |

**Honest positioning**: Semgrep outperforms CodeSentinel on rule-based coverage breadth. CodeQL outperforms on dataflow depth. Snyk outperforms on supply-chain dependency analysis. CodeSentinel is pedagogically useful in ways these tools are not — every finding is grounded in a cited authoritative source, the adversarial Evaluator is a novel anti-hallucination pattern, and the entire system runs reproducibly without an API key. The system is not a replacement for mature SAST tools; it is a demonstration that agent-based LLM orchestration can close specific failure modes (hallucination, omission, lack of traceability) that single-prompt review exhibits.

A comparison protocol for running CodeSentinel against Semgrep on real open-source Python codebases is specified in §10.10 of the technical report and implemented in `eval/semgrep_compare.py`.

---

## Portfolio Piece

CodeSentinel is designed as a portfolio piece for the 2026 software-engineering and AI-engineering job market. It demonstrates six skills that appear repeatedly in AI-engineering job postings from Anthropic, Google, Microsoft, AWS, Cisco, and their open-source partner organizations.

1. **Agentic AI architecture.** Multi-agent graphs with explicit state transitions and conditional routing are the dominant pattern in production LLM applications in 2026. Anthropic's own Project Glasswing (launched April 2026) uses the same architectural pattern — rank before analyze, specialize per agent, validate with an independent pass — at industrial scale to find zero-day vulnerabilities in operating systems and web browsers. CodeSentinel demonstrates that pattern at academic scale with open tools.

2. **Retrieval-Augmented Generation with production rigor.** Three-tier backend fallback, semantic-boundary chunking, two-pass retrieval with lexical rerank, and citation-enforcement at the consumer end. This is the RAG pattern production systems actually use, not the toy single-backend setup often shown in tutorials.

3. **Rigorous LLM evaluation.** Dual-suite evaluation (10-sample hand-labeled toy suite plus 20-sample OWASP-Benchmark-style paired suite), paired statistical testing (McNemar's exact test, p = 0.0312 significant at α = 0.05), explicit Wilson confidence intervals, power analysis scoping the sample size required for conclusive inference, and honest decomposition of the two false positives rather than suppression.

4. **Security domain knowledge.** Grounded in OWASP Top 10 2025 and CWE taxonomy. Categories covered: CWE-89 (SQL injection), CWE-502 (deserialization), CWE-78 (command injection), CWE-327 (weak crypto), CWE-295 (TLS validation), CWE-94 (code injection), CWE-79 (XSS), CWE-798 (hard-coded credentials).

5. **Production engineering discipline.** 35 unit tests, three-tier dependency fallback, deterministic mock mode for CI, Makefile with reproducible targets, Pydantic schemas with dataclass fallback, explicit zero-retention design, reproducible benchmarks with committed per-sample results.

6. **Technical writing.** 23-page technical report with architecture section, methodology, measured results, power analysis, false-positive decomposition, scope-change accounting, ethical considerations, limitations, and extensive references. Standalone reviewer's guide. Portfolio-grade showcase page.

The project sits at the intersection of two skill areas the 2026 job market values most: **AI/LLM engineering** and **software security**. Amazon CodeGuru, Microsoft GitHub Copilot, Google Gemini Code Assist, and Snyk are all building in this space. This project demonstrates understanding not just of how to orchestrate LLMs but how to evaluate them rigorously for a safety-critical domain.

Links:
- GitHub repository: [github.com/AravindB98/CodeSentinel](https://github.com/AravindB98/CodeSentinel)
- Live interactive demo: [codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app](https://codesentinel-f2ggdvqeuwsj4pta5sk27s.streamlit.app)
- Project showcase: `website/index.html` in this repo, or deploy to GitHub Pages
- Technical report: [`docs/CodeSentinel_Technical_Report.pdf`](docs/CodeSentinel_Technical_Report.pdf)
- Author portfolio: [aravindbalaji.com](https://aravindbalaji.com)
- Author Substack (AI, quantum computing, infrastructure): [aravindbalaji1.substack.com](https://aravindbalaji1.substack.com)
- Author LinkedIn: [linkedin.com/in/aravind-balaji-17a7b2115](https://linkedin.com/in/aravind-balaji-17a7b2115)

---

## Engineering Notes (Post-Submission Fixes)

The following bugs were diagnosed and fixed after initial submission (April 20, 2026). All fixes are committed to `master`.

| Bug | Root cause | Fix |
|---|---|---|
| Pipeline produced 0 security findings | `StateGraph(dict)` in LangGraph 1.1.4 — the framework auto-infers TypedDict channels, so nodes received empty state on the first call | Changed to `StateGraph(CodeSentinelState)` in `graph/build_graph.py` |
| Security Sentinel suppressed all findings | `security.md` Rules 1+2 told the LLM to suppress findings when no perfect RAG citation existed | Relaxed both rules: cite closest topical passage, only suppress if confidence < 0.5 |
| Evaluator approved 0 findings vacuously | `_programmatic_check` returned APPROVED when no findings present, preventing any retry | Returns REJECTED with feedback when sentinel retries < 2 |
| Evaluator skipped LLM for non-empty findings | LLM layer short-circuited when programmatic check rejected | Always runs LLM when `has_findings=True` |
| Circuit breaker discarded approved findings | `assemble_report` used `verdict.approved_ids` which was empty after circuit-breaker fire | Passes all findings through when circuit breaker has fired |
| Quality Auditor crashed on large files | LLM returned truncated JSON; `rfind("}")` gave malformed middle JSON | Salvages complete finding objects by scanning for balanced braces with `finding_id` keys |
| Streamlit Cloud install failed | `langchain-core<0.5.0` is unsatisfiable with `langgraph>=1.1.0` (which requires `>=1.3.0`) | Bumped to `langchain-core>=1.3.0,<2.0.0` in `requirements.txt` |

---

## Honest Limitations

Every non-trivial system has limitations. These are ours, disclosed rather than suppressed.

1. **Evaluation scale is modest.** 10 hand-labeled samples plus 20 paired samples plus 29 verified synthetic samples is sufficient for a course project but not for a production claim. A 100-sample hand-labeled expansion is the top item in Future Work. Power analysis for the required sample size is in §10.9 of the technical report.

2. **RL is a demonstration, not an integrated contribution.** The UCB-1 bandit and REINFORCE policy gradient in `rl/` converge on synthetic reward surfaces but are not wired into the production agent graph. This is disclosed in four separate places (README rubric table, Abstract, §8 opening, Conclusion).

3. **Semgrep comparison ran on Flask production source — both tools found 0 findings.** The protocol specified in §10.10 was executed against Flask's `app.py` and `helpers.py` (April 2026). Semgrep: 0 findings in 10.6s, $0.00. CodeSentinel: 0 findings in 441.9s, ~$0.25. Overlap: 0, Semgrep-only: 0, CodeSentinel-only: 0. This is the **correct** result — Flask is hardened production code with no obvious vulnerabilities. Results committed to `eval/results/semgrep_comparison/`.

4. **Two characterized false positives.** On the paired suite, the multi-agent system produces one FP on MD5 used as a cache key (no contextual signal to distinguish from security use) and one FP on a dead-code vulnerable branch (no reachability analysis). Both are decomposed in §10.8 with three concrete mitigation paths.

5. **Language coverage is uneven.** The RAG corpus covers Python, JavaScript, and Java patterns, but the pattern-based mock detector is Python- and JavaScript-oriented. Java coverage in the mock is effectively zero. This is why the Java-based OWASP Benchmark was replaced with a Python paired suite in the spirit of the same methodology; documented in §10.11 of the technical report.

6. **Mock mode is not real-model performance.** All reported numbers were measured in deterministic mock-LLM mode. Real-LLM performance will differ — likely better on nuanced cases, likely similar on pattern-matchable ones. The mock is designed to mirror the structure of a real LLM's response given the same retrieval context; it is a reproducibility tool, not a substitute.

7. **Not a substitute for human review in regulated contexts.** Payment systems, medical devices, and other contexts where human accountability and traceable review processes are mandatory require review by humans. CodeSentinel is advisory, not authoritative.

---

## References

### Industry data on the code-review gap and AI-generated code

1. Veracode (2025). *State of Software Security 2025*. Scanned 1M+ applications; roughly half contain an OWASP Top 10 flaw.
2. OWASP Foundation (2025). *OWASP Top 10 2025*. Eighth edition; analyzed ~175,000 CVE records from the National Vulnerability Database.
3. Stack Overflow (2025). *2025 Developer Survey*. 49,000+ responses from 177 countries; 66% cite "almost right, but not quite" as the top AI-tool frustration.
4. Codacy (2025). *Code Review Process: Impact on Developer Productivity*. Survey of 680 developers; 6–20 minutes per review.
5. Ponamarev, V. (2025). "Developers Spend Only 11% of Their Time Coding." Industry productivity analysis.
6. IBM Security (2023). *Cost of a Data Breach Report*. Global average: $4.45 million per incident.

### Frameworks and techniques used

7. Chase, H. (2024). *LangChain and LangGraph documentation*. https://python.langchain.com/docs/langgraph
8. Lewis, P. et al. (2020). Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks. *NeurIPS 2020*.
9. Reimers, N. and Gurevych, I. (2019). Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks. *EMNLP 2019*.
10. Auer, P., Cesa-Bianchi, N., and Fischer, P. (2002). Finite-time Analysis of the Multiarmed Bandit Problem. *Machine Learning 47*.
11. Williams, R. J. (1992). Simple Statistical Gradient-Following Algorithms for Connectionist Reinforcement Learning. *Machine Learning 8*.
12. McNemar, Q. (1947). Note on the sampling error of the difference between correlated proportions or percentages. *Psychometrika 12(2)*.

### Security taxonomies and benchmarks

13. OWASP Foundation. *OWASP Benchmark Project*. https://owasp.org/www-project-benchmark/
14. OWASP-Benchmark GitHub organization. *BenchmarkJava: Java test suite for vulnerability-detection tools*. https://github.com/OWASP-Benchmark/BenchmarkJava
15. MITRE Corporation. *Common Weakness Enumeration (CWE)*. https://cwe.mitre.org/
16. OWASP Foundation. *OWASP Top 10 2025*. https://owasp.org/Top10/

### Contemporary industrial work on agentic code analysis

17. Anthropic (April 2026). *Project Glasswing: Securing Critical Software for the AI Era*. https://www.anthropic.com/glasswing
18. Anthropic Frontier Red Team (April 2026). *Claude Mythos Preview: Technical Notes on Vulnerability Discovery*. https://red.anthropic.com/2026/mythos-preview/

### Related commercial tools

19. Semgrep Inc. *Semgrep: Static analysis at ludicrous speed*. https://semgrep.dev
20. GitHub. *CodeQL: Semantic code analysis engine*. https://codeql.github.com
21. Snyk Ltd. *Snyk Code: AI-powered SAST*. https://snyk.io/product/snyk-code/
22. Bito AI. *CodeReviewAgent*. https://bito.ai/ai-code-review-agent/
23. Tabnine. *Code Review Agent*. https://www.tabnine.com/code-review-agent/

### Style guides and coding standards

24. van Rossum, G., Warsaw, B., and Coghlan, A. *PEP 8: Style Guide for Python Code*.
25. Google. *Google Python Style Guide*. https://google.github.io/styleguide/pyguide.html
26. Airbnb. *Airbnb JavaScript Style Guide*. https://github.com/airbnb/javascript

---

## License

Copyright (c) 2026 Aravind Balaji.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**RAG corpus licensing (not covered by the above MIT grant):**
- OWASP Top 10 content: used under Creative Commons Attribution-ShareAlike 4.0.
- CWE taxonomy: public domain (MITRE).
- Style guide excerpts: used from publicly available documents under their respective licenses.

---

## Citation

If you reference CodeSentinel in academic or professional work:

```bibtex
@misc{balaji2026codesentinel,
  author       = {Balaji, Aravind},
  title        = {{CodeSentinel}: A Multi-Agent Retrieval-Augmented Generative AI
                  System for Automated Code Review and Vulnerability Detection},
  year         = {2026},
  howpublished = {INFO 7375 Final Project, Northeastern University},
  note         = {Available at https://github.com/AravindB98/CodeSentinel}
}
```

Plain-text form:

> Balaji, A. (2026). *CodeSentinel: A Multi-Agent Retrieval-Augmented Generative AI System for Automated Code Review and Vulnerability Detection*. INFO 7375 Final Project, Northeastern University College of Engineering.

---

## Acknowledgments

Built as the final project for INFO 7375 (Prompt Engineering and Generative AI) under **Professor Nik Bear Brown**, Spring 2026. The project's architectural thinking was shaped by Professor Brown's framing of computational skepticism and adversarial evaluation as first-class design principles for LLM systems.

Developed in parallel with the April 15 INFO 7375 Take-Home Final on reinforcement learning for agentic systems. The two submissions share a codebase; this project foregrounds the generative AI architecture, the Take-Home foregrounds the RL formulation.


The Claude Mythos and Project Glasswing material published by Anthropic in April 2026 provided valuable late-stage context for framing the architectural pattern this project demonstrates.

---

*Last updated: April 20, 2026. For the latest measured results, see `eval/results/` — CSV outputs are authoritative over any number in this document.*
