"""
Semgrep vs. CodeSentinel comparison harness.

This script implements the real-world comparison protocol specified in
Section 10.10 of the Technical Report. It runs both systems against the
same set of source files and produces a side-by-side finding table,
overlap metrics, and a simple cost/latency summary.

Prerequisites:
  pip install semgrep        # needs network; not included in requirements.txt
  export ANTHROPIC_API_KEY=sk-ant-...   # real LLM mode for CodeSentinel

Example usage:
  # Clone a small target project
  git clone --depth 1 https://github.com/pallets/flask /tmp/flask
  # Pick some files to compare on
  python -m eval.semgrep_compare --files /tmp/flask/src/flask/app.py \
                                         /tmp/flask/src/flask/helpers.py \
                                 --out eval/results/semgrep_comparison/

The script is intentionally minimal: its job is to produce a CSV that a
human can adjudicate in 15 minutes, not to auto-adjudicate.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(message)s")


@dataclass
class Finding:
    """Normalized finding from either system."""
    source: str           # "semgrep" or "codesentinel"
    file: str
    line: int
    cwe_id: Optional[str]
    category: str
    severity: str
    snippet: str
    rule_or_rag: str       # semgrep rule id, or CodeSentinel rag_source::passage
    message: str

    def location_key(self) -> Tuple[str, int]:
        """For overlap detection, we compare file + line (exact)."""
        return (self.file, self.line)


# --- Semgrep ---

def run_semgrep(files: List[Path], config: str = "auto") -> Tuple[List[Finding], float]:
    """Run `semgrep --config=auto` on a list of files. Returns (findings, elapsed)."""
    if not files:
        return [], 0.0
    cmd = ["semgrep", f"--config={config}", "--json", "--quiet"] + [str(f) for f in files]
    t0 = time.time()
    try:
        out = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.error("semgrep not installed. Install via: pip install semgrep")
        sys.exit(2)
    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after 300s")
        return [], time.time() - t0
    elapsed = time.time() - t0
    if out.returncode not in (0, 1):  # 0=no findings, 1=findings present
        logger.error("semgrep failed (rc=%d): %s", out.returncode, out.stderr[:500])
        return [], elapsed

    findings: List[Finding] = []
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        logger.error("semgrep output not JSON: %s", out.stdout[:300])
        return [], elapsed

    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        cwe = meta.get("cwe")
        # semgrep cwe field is often a list of strings like "CWE-89: SQL Injection"
        cwe_id = None
        if isinstance(cwe, list) and cwe:
            cwe_id = cwe[0].split(":")[0].strip() if isinstance(cwe[0], str) else None
        elif isinstance(cwe, str):
            cwe_id = cwe.split(":")[0].strip()

        findings.append(Finding(
            source="semgrep",
            file=r.get("path", "?"),
            line=int(r.get("start", {}).get("line", 0)),
            cwe_id=cwe_id,
            category=(meta.get("category") or r.get("check_id", "")).strip(),
            severity=(r.get("extra", {}).get("severity") or "UNKNOWN").upper(),
            snippet=(r.get("extra", {}).get("lines") or "")[:300],
            rule_or_rag=r.get("check_id", "unknown-rule"),
            message=(r.get("extra", {}).get("message") or "")[:500],
        ))
    return findings, elapsed


# --- CodeSentinel ---

def run_codesentinel(files: List[Path]) -> Tuple[List[Finding], float, float]:
    """Run CodeSentinel on each file. Returns (findings, elapsed, approx_cost_usd).

    Cost estimate is rough: assumes Claude Sonnet pricing at ~$3 per million
    input tokens and ~$15 per million output tokens, approximated from
    token counts in the response when available."""
    from graph.build_graph import build_graph

    t0 = time.time()
    all_findings: List[Finding] = []
    runner = build_graph()

    for f in files:
        try:
            code = f.read_text(encoding="utf-8")
        except Exception as e:
            logger.warning("Could not read %s: %s", f, e)
            continue
        state = {
            "input_code": code,
            "language": _infer_language(f),
            "run_id": f"cmp-{f.stem}",
        }
        try:
            result = runner.invoke(state)
        except Exception as e:
            logger.warning("CodeSentinel failed on %s: %s", f, e)
            continue

        verdict = result.get("evaluator_verdict")
        approved = set(verdict.approved_ids) if verdict else set()

        for sf in result.get("security_findings", []):
            if sf.finding_id not in approved:
                continue
            all_findings.append(Finding(
                source="codesentinel",
                file=str(f),
                line=sf.evidence.line_start,
                cwe_id=sf.cwe_id,
                category=sf.category,
                severity=sf.severity.value if hasattr(sf.severity, "value") else str(sf.severity),
                snippet=sf.evidence.snippet[:300],
                rule_or_rag=f"{sf.rag_source.doc}::{sf.rag_source.passage_id}",
                message=sf.fix[:500],
            ))
    elapsed = time.time() - t0

    # Rough cost estimate - very approximate, meant for order-of-magnitude sense
    is_mock = os.getenv("CODESENTINEL_MOCK_LLM") == "1" or not os.getenv("ANTHROPIC_API_KEY")
    approx_cost = 0.0 if is_mock else _estimate_cost(files)
    return all_findings, elapsed, approx_cost


def _infer_language(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".py":
        return "python"
    if suf in (".js", ".ts", ".jsx", ".tsx"):
        return "javascript"
    if suf == ".java":
        return "java"
    return "unknown"


def _estimate_cost(files: List[Path]) -> float:
    """Very rough: ~$3/MTok in, ~$15/MTok out, ~500 output tokens per agent * 3 agents."""
    total_chars = sum(f.stat().st_size for f in files if f.exists())
    approx_input_tokens = total_chars / 4 * 3   # 3 agent passes
    approx_output_tokens = len(files) * 1500    # ~1.5k output tokens per file
    return (approx_input_tokens / 1e6 * 3.0) + (approx_output_tokens / 1e6 * 15.0)


# --- Comparison ---

def compare(sem: List[Finding], cs: List[Finding], line_tolerance: int = 3) -> Dict:
    """
    Classify findings as:
      both: same file, line within tolerance, compatible CWE (or one is None)
      semgrep_only / codesentinel_only: the remainder
    """
    matched_sem: Set[int] = set()
    matched_cs: Set[int] = set()
    pairs: List[Tuple[Finding, Finding]] = []

    for i, s in enumerate(sem):
        for j, c in enumerate(cs):
            if j in matched_cs:
                continue
            if s.file != c.file:
                continue
            if abs(s.line - c.line) > line_tolerance:
                continue
            if s.cwe_id and c.cwe_id and s.cwe_id != c.cwe_id:
                continue
            matched_sem.add(i)
            matched_cs.add(j)
            pairs.append((s, c))
            break

    return {
        "overlap_count": len(pairs),
        "semgrep_only": [sem[i] for i in range(len(sem)) if i not in matched_sem],
        "codesentinel_only": [cs[j] for j in range(len(cs)) if j not in matched_cs],
        "overlap_pairs": pairs,
    }


# --- Reporting ---

def write_csv(findings: List[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source", "file", "line", "cwe_id", "category", "severity",
                    "rule_or_rag", "snippet", "message"])
        for x in findings:
            w.writerow([x.source, x.file, x.line, x.cwe_id or "", x.category,
                        x.severity, x.rule_or_rag, x.snippet, x.message])


def write_adjudication_template(comparison: Dict, path: Path) -> None:
    """Produces a human-readable adjudication worksheet.

    The human opens this file, looks at each unique finding, and marks it
    TP / FP / AMBIG in the right column. Takes ~15 minutes on 20 findings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("# Adjudication Worksheet\n\n")
        f.write("For each finding below, review the code at the given location "
                "and mark the `adjudication` column as TP (true positive), "
                "FP (false positive), or AMBIG (ambiguous).\n\n")

        f.write(f"## Overlap ({comparison['overlap_count']} pairs)\n\n")
        f.write("| file | line | semgrep_cwe | cs_cwe | adjudication |\n")
        f.write("|---|---|---|---|---|\n")
        for s, c in comparison["overlap_pairs"]:
            f.write(f"| {s.file} | {s.line} | {s.cwe_id or '-'} | {c.cwe_id or '-'} | TBD |\n")

        f.write(f"\n## Semgrep only ({len(comparison['semgrep_only'])} findings)\n\n")
        f.write("| file | line | rule | cwe | message | adjudication |\n")
        f.write("|---|---|---|---|---|---|\n")
        for x in comparison["semgrep_only"]:
            f.write(f"| {x.file} | {x.line} | `{x.rule_or_rag}` | {x.cwe_id or '-'} | "
                    f"{x.message[:120]}... | TBD |\n")

        f.write(f"\n## CodeSentinel only ({len(comparison['codesentinel_only'])} findings)\n\n")
        f.write("| file | line | citation | cwe | fix | adjudication |\n")
        f.write("|---|---|---|---|---|---|\n")
        for x in comparison["codesentinel_only"]:
            f.write(f"| {x.file} | {x.line} | `{x.rule_or_rag}` | {x.cwe_id or '-'} | "
                    f"{x.message[:120]}... | TBD |\n")


def write_summary(
    sem: List[Finding], cs: List[Finding], comparison: Dict,
    sem_elapsed: float, cs_elapsed: float, approx_cost: float, path: Path,
) -> None:
    n_sem, n_cs = len(sem), len(cs)
    overlap = comparison["overlap_count"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("# Semgrep vs. CodeSentinel Comparison\n\n")
        f.write(f"## Volume\n")
        f.write(f"- Semgrep findings: {n_sem}\n")
        f.write(f"- CodeSentinel findings: {n_cs}\n")
        f.write(f"- Overlap: {overlap}\n")
        if n_sem:
            f.write(f"- Overlap / Semgrep total: {overlap/n_sem:.2%}\n")
        if n_cs:
            f.write(f"- Overlap / CodeSentinel total: {overlap/n_cs:.2%}\n")
        f.write(f"\n## Cost & Latency\n")
        f.write(f"- Semgrep elapsed: {sem_elapsed:.2f}s (cost: $0.00)\n")
        f.write(f"- CodeSentinel elapsed: {cs_elapsed:.2f}s "
                f"(approx cost: ${approx_cost:.4f})\n")
        f.write(f"\n## Next step\n\n")
        f.write("Review `adjudication.md` and fill in TP/FP/AMBIG for each unique "
                "finding. Then recompute precision per system.\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--files", nargs="+", required=True, help="Source files to analyze")
    p.add_argument("--out", default="eval/results/semgrep_comparison/",
                   help="Output directory for CSV + summary + adjudication worksheet")
    p.add_argument("--config", default="auto",
                   help="Semgrep config (default: auto)")
    args = p.parse_args()

    files = [Path(f) for f in args.files]
    missing = [f for f in files if not f.exists()]
    if missing:
        logger.error("Files not found: %s", missing)
        sys.exit(1)

    logger.info("Running Semgrep on %d file(s) with config=%s ...", len(files), args.config)
    sem, sem_t = run_semgrep(files, args.config)
    logger.info("Semgrep: %d finding(s) in %.2fs", len(sem), sem_t)

    logger.info("Running CodeSentinel on %d file(s) ...", len(files))
    cs, cs_t, cost = run_codesentinel(files)
    logger.info("CodeSentinel: %d finding(s) in %.2fs (approx $%.4f)", len(cs), cs_t, cost)

    comparison = compare(sem, cs)
    out = Path(args.out)

    write_csv(sem + cs, out / "all_findings.csv")
    write_adjudication_template(comparison, out / "adjudication.md")
    write_summary(sem, cs, comparison, sem_t, cs_t, cost, out / "summary.md")

    logger.info("Wrote %s/{all_findings.csv,adjudication.md,summary.md}", out)
    logger.info("Overlap: %d findings; Semgrep-only: %d; CodeSentinel-only: %d",
                comparison["overlap_count"],
                len(comparison["semgrep_only"]),
                len(comparison["codesentinel_only"]))


if __name__ == "__main__":
    main()
