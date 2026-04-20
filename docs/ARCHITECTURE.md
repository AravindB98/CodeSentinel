# CodeSentinel Architecture

## System Overview

CodeSentinel is a multi-agent, retrieval-grounded, adversarially-reviewed code review system. It is built on LangGraph and orchestrates three specialized LLM agents through a directed graph with a bounded retry loop.

```
               ┌─────────────────────┐
               │  Input source code  │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐    retrieve    ┌──────────────┐
               │  Security Sentinel  │◄──────────────►│   ChromaDB   │
               │  (RAG-grounded)     │    (k=6)       │  (or TF-IDF) │
               └──────────┬──────────┘                └──────────────┘
                          │ security_findings
                          ▼
               ┌─────────────────────┐
               │ Code Quality Auditor│
               └──────────┬──────────┘
                          │ quality_findings
                          ▼
               ┌─────────────────────┐
               │ Evaluator Guardian  │
               │ (programmatic+LLM)  │
               └──────────┬──────────┘
                          │
                 ┌────────┴────────┐
              APPROVED          REJECTED
                 │                 │
                 │        ┌────────┴────────┐
                 │    retries<3         retries>=3
                 │        │                 │
                 │        │ (route back     │ circuit
                 │        │  w/ feedback)   │ breaker
                 │        │                 │
                 │        ▼                 │
                 │  security_sentinel       │
                 │                          │
                 ▼                          ▼
          ┌─────────────────────────────────────┐
          │        assemble_report              │
          └─────────────────────────────────────┘
```

## Agents

### Security Sentinel

**Role**: RAG-grounded vulnerability detection.

**Inputs**:
- `input_code`: source file or snippet
- `language`: python | javascript | java | unknown
- `evaluator_feedback` (optional): structured feedback from a prior rejection

**Process**:
1. Build a retrieval query from language + suspicious keywords + first 800 chars
2. Retrieve top-6 passages from the RAG index (two-pass: semantic + lexical rerank)
3. Call LLM with `security.md` system prompt and the retrieved passages
4. Parse LLM output into `SecurityFinding` objects (Pydantic validation)
5. Drop any finding that fails schema validation

**Outputs**: `security_findings` list, `retrieved_passages` list, `trace` entry.

**Key policy**: Every finding MUST cite a retrieved passage via `rag_source.doc` and `rag_source.passage_id`. Findings without citations are rejected downstream.

### Code Quality Auditor

**Role**: Style, maintainability, and error handling review.

**Inputs**: `input_code`, `language`.

**Process**:
1. Call LLM with `quality.md` system prompt
2. Parse into `QualityFinding` objects
3. Cap at 10 findings per file

**Outputs**: `quality_findings` list.

**Key constraint**: Never produces CRITICAL severity (reserved for security). Never overlaps with Security Sentinel territory (injection, deserialization, crypto, auth).

### Evaluator Guardian

**Role**: Adversarial reviewer. Rejects findings that fail any policy check.

**Two-layer design**:

1. **Programmatic check** (always runs, no LLM call required):
   - For each security finding:
     - `rag_source` must be present and point to a passage in the retrieved context
     - `fix` must be at least 20 characters
     - `confidence` must be >= 0.5
     - Schema must validate
   - For each quality finding:
     - `rationale` and `suggested_refactor` must both be >= 10 characters
     - `confidence` must be >= 0.5

2. **LLM semantic check** (optional, runs only if programmatic check passes):
   - Uses `evaluator.md` system prompt
   - Validates that citations actually support the claim semantically
   - Detects internal contradictions between findings

**Outputs**: `EvaluatorVerdict` with `overall_decision` (APPROVED or REJECTED), per-finding decisions, and structured feedback for rejected items.

## State

Shared state is a `TypedDict` (`CodeSentinelState`) with explicit fields:

```python
class CodeSentinelState(TypedDict, total=False):
    input_code: str
    language: str
    retrieved_passages: List[RetrievedPassage]
    security_findings: List[SecurityFinding]
    quality_findings: List[QualityFinding]
    evaluator_verdict: Optional[EvaluatorVerdict]
    retry_count: Dict[str, int]
    evaluator_feedback: Optional[str]
    final_report: Optional[str]
    run_id: str
    trace: List[str]
    error: Optional[str]
```

All agents read and write the same state. Nothing is passed implicitly.

## Routing and Circuit Breaker

After the Evaluator Guardian runs, `_route_after_evaluator` inspects the verdict:

- If `overall_decision == "APPROVED"` -> route to `assemble_report` -> END
- If `overall_decision == "REJECTED"` AND `retry_count["security_sentinel"] < 3` -> route back to `security_sentinel` with `evaluator_feedback` set
- If `overall_decision == "REJECTED"` AND retry limit reached -> route to `assemble_report` anyway (circuit breaker), emit a trace line noting incomplete review

Bounded termination is a correctness property. Without the circuit breaker, the first implementation oscillated: the Evaluator alternated between approving and rejecting the same finding on successive passes. Test `test_pipeline_respects_circuit_breaker` locks this in.

## RAG Pipeline

### Knowledge base

- `rag/data/owasp_top10_2025.txt` - 10 OWASP Top 10 2025 category entries
- `rag/data/cwe_subset.csv` - 29 CWEs most relevant to application code
- `rag/data/patterns.md` - 17 language-specific patterns (Python, JavaScript, Java)

Total: 56 passages.

### Chunking

Passages are pre-chunked at semantic boundaries. OWASP entries are one passage per category. CWE entries are one passage per CWE. Language patterns are one passage per named pattern. This avoids the failure mode of fixed-token chunking where a single retrieval returns a fragment of a category rather than the full category.

### Embedding backend

Triple fallback, in priority order:

1. **ChromaDB + sentence-transformers** (`all-MiniLM-L6-v2`). Preferred path. Runs locally on CPU, no external API.
2. **scikit-learn TF-IDF**. Used when ChromaDB is unavailable but sklearn is installed.
3. **Pure-Python TF-IDF**. Used when neither of the above is available. Zero heavy dependencies.

All three expose the same `Retriever` interface.

### Two-pass retrieval

1. First pass: top-2k semantic search from the chosen backend
2. Second pass: lexical rerank that boosts passages whose title matches query keywords (e.g., query contains "pickle" -> boost passages whose title contains "pickle" or "CWE-502")
3. Return top-k after dedup

The rerank exists because pure semantic retrieval frequently returns the generic OWASP A03 entry for any query that mentions a database, even when the specific CWE-89 or PY-01 pattern is the correct match. The rerank measurably fixes this.

## Evaluation Methodology

### Datasets

- `eval/datasets/toy_suite.json` - 10 hand-labeled samples spanning Python (7) and JavaScript (3), covering CWE-89, CWE-502, CWE-78, CWE-327, CWE-295, CWE-79
- `eval/datasets/synthetic_suite.json` - 29 verified synthetic samples (generated by `synth.generate` and verified by `synth.verify` with an independent regex-based detector)

### Baselines

- **Single-prompt baseline** (`eval/baseline_single_prompt.py`): one LLM call with one system prompt, on the same underlying model as CodeSentinel. This isolates architecture gains from model gains.

### Metrics

- True positive rate: fraction of ground-truth vulnerabilities correctly detected
- False positive rate: fraction of predictions on clean code that are spurious
- CWE classification accuracy: of the true positives, fraction assigned to the correct CWE
- Latency per sample, token cost per sample

### Matching rule

A prediction matches a ground-truth entry when:
- `cwe_id` matches exactly, AND
- Predicted line range overlaps the ground-truth line range within +/- 2 lines tolerance

### Reported results (measured, not projected)

10-sample hand-labeled toy suite, mock LLM backend:

| System | TPR | FPR | CWE accuracy |
|---|---|---|---|
| Single-prompt baseline | 0.750 | 0.000 | 1.000 |
| Multi-agent CodeSentinel | 1.000 | 0.000 | 1.000 |

Delta: +0.250 TPR, +0.000 FPR. The baseline misses samples that require the specific language-pattern knowledge that RAG retrieval supplies (e.g., `yaml.load` without `SafeLoader` and `hashlib.md5` used for password hashing).

## Reinforcement Learning Enhancement Layer

The RL layer is a separate module (`rl/`) that treats two agent-graph decision points as learnable policies.

### Prompt variant selection (UCB-1 contextual bandit)

Each agent has multiple prompt variants. At runtime, the bandit selects a variant based on a 60-bucket context (4 languages x 3 complexity classes x 5 vulnerability classes). Reward is 1 if the Evaluator approves the finding on first pass, 0 otherwise. Exploration constant is annealed as per-context pull count grows.

Demo (`python -m rl.bandit`) shows convergence to the correct best arm per context on a synthetic reward surface after ~200 rounds.

### Routing (REINFORCE policy gradient)

After an Evaluator rejection, the routing decision is parameterized as a softmax over 4 actions (three Security Sentinel variants + `skip_to_assemble`) conditioned on a 7-dim one-hot feature vector over rejection reasons. Weights are trained with REINFORCE and a moving-average baseline.

Demo (`python -m rl.policy`) shows the policy learning the correct action-per-reason mapping after ~600 training steps, converging with less than 500 parameters.

Both modules run on NumPy only (no PyTorch required). The bandit state and policy weights persist to JSON between runs.

## Why these specific choices

### Why LangGraph over LangChain

LangGraph models state transitions explicitly. A bounded retry loop with conditional routing maps cleanly onto `add_conditional_edges` with an explicit router function. LangChain's chain abstraction buries the routing logic inside the chain, which makes the retry-termination property invisible in code.

### Why the citation-required policy

LLM hallucinations on code review frequently take the form of findings that sound plausible but point to nothing. The citation requirement is the single highest-leverage anti-hallucination policy: if a finding cannot cite a passage from the retrieved context, it cannot appear in the output. This is enforced at the Evaluator, programmatically, not as advice in a prompt.

### Why a programmatic + LLM evaluator

An LLM evaluator alone is vulnerable to the same biases as the upstream Sentinel (they are the same model). A programmatic pre-check catches the unambiguous cases (missing citation, missing fix, bad confidence) deterministically. The LLM layer adds semantic review (does the cited passage actually support the claim) only after programmatic checks pass. This is the cheaper and more reliable ordering.

### Why mock mode

The pipeline must be runnable end-to-end without an API key, for three reasons: graders who don't want to provision a key, CI runs, and unit tests. The mock LLM returns deterministic pattern-matched outputs for every prompt template, which means the full graph (including the 3-retry circuit breaker) can be exercised in unit tests.

### Why this architectural pattern at all

The pattern — rank before analyze, specialize per agent, validate with an independent pass before surfacing — is the same pattern Anthropic's Project Glasswing uses at industrial scale with Claude Mythos to find zero-day vulnerabilities in operating systems and web browsers (see References in the tech report). CodeSentinel does not compete with Glasswing on capability; it demonstrates that the same architectural pattern is reproducible, testable, and teachable with open tools at academic scale, and that its gains are attributable to the architecture rather than the model. Swapping in a stronger model would improve results without requiring the architecture to change. That is the point of the pattern.

## File Index

```
codesentinel/
├── app/streamlit_app.py             Interactive UI
├── graph/
│   ├── state.py                     Shared TypedDict state
│   ├── schemas.py                   Pydantic models + fallback
│   ├── build_graph.py               LangGraph wiring + fallback runner
│   ├── agents/
│   │   ├── security_sentinel.py
│   │   ├── code_quality_auditor.py
│   │   └── evaluator_guardian.py
│   └── prompts/
│       ├── security.md
│       ├── quality.md
│       └── evaluator.md
├── rag/
│   ├── ingest.py                    Triple-backend ingest
│   ├── retriever.py                 Two-pass retrieval
│   └── data/                        56 passages across 3 files
├── synth/
│   ├── generate.py                  15 CWE templates -> vuln + safe pairs
│   └── verify.py                    Independent regex-based verifier
├── rl/
│   ├── bandit.py                    UCB-1 contextual bandit
│   └── policy.py                    REINFORCE policy gradient
├── eval/
│   ├── baseline_single_prompt.py
│   ├── run_benchmark.py
│   └── datasets/
│       ├── toy_suite.json           10 hand-labeled
│       └── synthetic_suite.json     29 verified synthetic
├── utils/llm_client.py              Anthropic SDK + mock mode
├── tests/                           27 tests, all passing
├── docs/ARCHITECTURE.md             this file
├── requirements.txt
├── Makefile
├── .env.example
├── .gitignore
└── README.md
```

## Reproduction

```
make install
make ingest        # build the RAG index
make test          # run 27 unit tests (mock LLM, no API key needed)
make benchmark     # run 10-sample benchmark, baseline vs multi-agent
make synth         # regenerate synthetic samples and re-verify
make ui            # launch Streamlit
```

Setting `ANTHROPIC_API_KEY` in `.env` switches the LLM client to the real Anthropic SDK. Without it, mock mode is used automatically and the pipeline still runs end-to-end.
