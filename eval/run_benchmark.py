"""
Evaluation harness for CodeSentinel.

Runs:
  - Single-prompt baseline
  - Multi-agent CodeSentinel

over the 10-sample toy suite, computes TPR / FPR / CWE accuracy, and
writes results to eval/results/<timestamp>/.

Usage:
  python -m eval.run_benchmark                  # full comparison
  python -m eval.run_benchmark --mode baseline  # baseline only
  python -m eval.run_benchmark --mode multi     # multi-agent only
  python -m eval.run_benchmark --sample TOY-001 # single sample debug
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from eval.baseline_single_prompt import run_baseline_dispatch
from graph.build_graph import build_graph

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)

SUITE_PATH = Path(__file__).resolve().parent / "datasets" / "toy_suite.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


def load_suite(path: Path = SUITE_PATH) -> List[Dict]:
    return json.loads(path.read_text(encoding="utf-8"))["samples"]


def findings_to_dicts(findings) -> List[Dict]:
    out = []
    for f in findings:
        out.append({
            "finding_id": f.finding_id,
            "cwe_id": f.cwe_id,
            "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "confidence": f.confidence,
            "line_start": f.evidence.line_start,
            "line_end": f.evidence.line_end,
        })
    return out


def compute_metrics(predictions: List[Dict], ground_truth: List[Dict],
                    tolerance: int = 2) -> Dict[str, float]:
    """Compute TP, FP, FN, TPR, FPR, CWE accuracy for a single sample.

    A prediction matches a ground-truth entry if:
      - cwe_id matches exactly, AND
      - predicted line range overlaps with ground-truth line range (+/- tolerance)
    """
    matched_gt = set()
    matched_pred = set()
    cwe_correct = 0

    for p_idx, pred in enumerate(predictions):
        for gt_idx, gt in enumerate(ground_truth):
            if gt_idx in matched_gt:
                continue
            if pred["cwe_id"] != gt["cwe_id"]:
                continue
            p_s, p_e = pred["line_start"], pred["line_end"]
            g_s, g_e = gt["line_start"], gt["line_end"]
            if p_e + tolerance >= g_s and p_s - tolerance <= g_e:
                matched_gt.add(gt_idx)
                matched_pred.add(p_idx)
                cwe_correct += 1
                break

    tp = len(matched_gt)
    fn = len(ground_truth) - tp
    fp = len(predictions) - len(matched_pred)

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "num_pred": len(predictions),
        "num_gt": len(ground_truth),
        "cwe_correct": cwe_correct,
    }


def aggregate(per_sample: List[Dict]) -> Dict[str, float]:
    """Compute aggregate metrics across samples."""
    total_tp = sum(s["tp"] for s in per_sample)
    total_fp = sum(s["fp"] for s in per_sample)
    total_fn = sum(s["fn"] for s in per_sample)
    total_gt = sum(s["num_gt"] for s in per_sample)
    total_pred = sum(s["num_pred"] for s in per_sample)
    total_cwe = sum(s["cwe_correct"] for s in per_sample)

    tpr = total_tp / total_gt if total_gt > 0 else 0.0
    # FPR as precision-inverted: false positives / total predictions
    fpr = total_fp / total_pred if total_pred > 0 else 0.0
    cwe_acc = total_cwe / total_tp if total_tp > 0 else 0.0

    return {
        "tp": total_tp, "fp": total_fp, "fn": total_fn,
        "tpr": round(tpr, 3),
        "fpr": round(fpr, 3),
        "cwe_accuracy": round(cwe_acc, 3),
        "samples": len(per_sample),
    }


def run_multi_agent_one(sample: Dict) -> Dict:
    runner = build_graph()
    t0 = time.time()
    state = {
        "input_code": sample["code"],
        "language": sample["language"],
        "run_id": sample["sample_id"],
    }
    result = runner.invoke(state)
    elapsed = time.time() - t0

    verdict = result.get("evaluator_verdict")
    approved_ids = set(verdict.approved_ids) if verdict else set()
    all_findings = result.get("security_findings", [])
    approved = [f for f in all_findings if f.finding_id in approved_ids]

    return {
        "sample_id": sample["sample_id"],
        "predictions": findings_to_dicts(approved),
        "raw_all": findings_to_dicts(all_findings),
        "elapsed_sec": round(elapsed, 3),
        "retries": result.get("retry_count", {}),
        "trace": result.get("trace", []),
    }


def run_baseline_one(sample: Dict) -> Dict:
    t0 = time.time()
    findings = run_baseline_dispatch(sample["code"], sample["language"])
    elapsed = time.time() - t0
    return {
        "sample_id": sample["sample_id"],
        "predictions": findings_to_dicts(findings),
        "elapsed_sec": round(elapsed, 3),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["both", "baseline", "multi"], default="both")
    parser.add_argument("--sample", help="run only one sample_id")
    parser.add_argument("--suite", default=str(SUITE_PATH))
    args = parser.parse_args()

    samples = load_suite(Path(args.suite))
    if args.sample:
        samples = [s for s in samples if s["sample_id"] == args.sample]
        if not samples:
            logger.error("No sample with id=%s", args.sample)
            sys.exit(1)

    # Output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / ts
    out.mkdir(parents=True, exist_ok=True)
    logger.info("Results -> %s", out)

    baseline_per = []
    multi_per = []

    for sample in samples:
        gt = sample["ground_truth"]
        logger.info("Sample %s (lang=%s, gt=%d)", sample["sample_id"],
                    sample["language"], len(gt))

        if args.mode in ("both", "baseline"):
            b = run_baseline_one(sample)
            m = compute_metrics(b["predictions"], gt)
            b.update(m)
            baseline_per.append(b)
            logger.info("  baseline: pred=%d tp=%d fp=%d fn=%d (%.2fs)",
                        len(b["predictions"]), m["tp"], m["fp"], m["fn"], b["elapsed_sec"])

        if args.mode in ("both", "multi"):
            mm = run_multi_agent_one(sample)
            metrics = compute_metrics(mm["predictions"], gt)
            mm.update(metrics)
            multi_per.append(mm)
            logger.info("  multi:    pred=%d tp=%d fp=%d fn=%d (%.2fs)",
                        len(mm["predictions"]), metrics["tp"], metrics["fp"], metrics["fn"],
                        mm["elapsed_sec"])

    # Write per-sample results
    if baseline_per:
        (out / "baseline_per_sample.json").write_text(
            json.dumps(baseline_per, indent=2), encoding="utf-8")
    if multi_per:
        (out / "multi_per_sample.json").write_text(
            json.dumps(multi_per, indent=2), encoding="utf-8")

    # Aggregate
    summary_lines = ["# CodeSentinel Evaluation Summary", f"Timestamp: {ts}",
                     f"Samples: {len(samples)}", ""]
    if baseline_per:
        agg_b = aggregate(baseline_per)
        summary_lines.extend([
            "## Single-prompt Baseline",
            f"- TPR: {agg_b['tpr']}", f"- FPR: {agg_b['fpr']}",
            f"- CWE Accuracy: {agg_b['cwe_accuracy']}",
            f"- TP={agg_b['tp']}, FP={agg_b['fp']}, FN={agg_b['fn']}",
            "",
        ])
    if multi_per:
        agg_m = aggregate(multi_per)
        summary_lines.extend([
            "## Multi-agent CodeSentinel",
            f"- TPR: {agg_m['tpr']}", f"- FPR: {agg_m['fpr']}",
            f"- CWE Accuracy: {agg_m['cwe_accuracy']}",
            f"- TP={agg_m['tp']}, FP={agg_m['fp']}, FN={agg_m['fn']}",
            "",
        ])
    if baseline_per and multi_per:
        delta_tpr = agg_m['tpr'] - agg_b['tpr']
        delta_fpr = agg_m['fpr'] - agg_b['fpr']
        delta_cwe = agg_m['cwe_accuracy'] - agg_b['cwe_accuracy']
        summary_lines.extend([
            "## Delta (multi - baseline)",
            f"- TPR: {delta_tpr:+.3f}", f"- FPR: {delta_fpr:+.3f}",
            f"- CWE Accuracy: {delta_cwe:+.3f}",
            "",
        ])

        # --- McNemar's exact test (paired comparison) ---
        # For each ground-truth finding, classify whether each system detected it.
        # b_only: baseline caught it, multi did not (discordant favoring baseline)
        # m_only: multi caught it, baseline did not (discordant favoring multi)
        # Concordant cases (both caught or both missed) are ignored by McNemar.
        b_by_id = {b["sample_id"]: b for b in baseline_per}
        b_only = m_only = both = neither = 0
        for m in multi_per:
            sid = m["sample_id"]
            b = b_by_id.get(sid, {})
            # Per-GT comparison: sample's TP is a count of correctly-detected GT findings.
            # For a paired test we compare per-sample detection, treating each sample as
            # one paired observation: "did at least one system catch everything?"
            b_caught_all = (b.get("fn", 0) == 0 and b.get("num_gt", 0) > 0)
            m_caught_all = (m.get("fn", 0) == 0 and m.get("num_gt", 0) > 0)
            if b_caught_all and m_caught_all:
                both += 1
            elif b_caught_all and not m_caught_all:
                b_only += 1
            elif m_caught_all and not b_caught_all:
                m_only += 1
            else:
                neither += 1

        # Exact binomial two-sided p-value under H0: each discordant pair is 50/50
        n_disc = b_only + m_only
        p_value: Optional[float] = None
        if n_disc > 0:
            # two-sided exact test: 2 * min(one-sided tail probabilities)
            k = min(b_only, m_only)
            # sum of binomial PMF from 0..k with p=0.5
            from math import comb
            tail = sum(comb(n_disc, i) for i in range(k + 1)) / (2 ** n_disc)
            p_value = min(1.0, 2 * tail)

        summary_lines.extend([
            "## McNemar's Exact Test (paired per-sample)",
            f"- Samples where only baseline detected all GT findings (b_only): {b_only}",
            f"- Samples where only multi-agent detected all GT findings (m_only): {m_only}",
            f"- Both systems detected all: {both}",
            f"- Neither detected all (or no GT): {neither}",
            f"- Discordant pairs: {n_disc}",
        ])
        if p_value is None:
            summary_lines.append("- No discordant pairs: test not applicable.")
        else:
            summary_lines.append(f"- Two-sided exact p-value: {p_value:.4f}")
            if p_value <= 0.05:
                direction = "multi-agent" if m_only > b_only else "baseline"
                summary_lines.append(f"- Result: direction favors {direction}, p <= 0.05.")
            else:
                summary_lines.append(
                    f"- Result: observed direction favors "
                    f"{'multi-agent' if m_only > b_only else 'baseline'}, "
                    f"but with only {n_disc} discordant pair(s) the test cannot reach "
                    "conventional significance (p>0.05). A run against a larger suite "
                    "would be required to claim statistical superiority."
                )

    summary = "\n".join(summary_lines)
    (out / "summary.md").write_text(summary, encoding="utf-8")
    print()
    print(summary)

    # Also write CSV for easy import
    if baseline_per and multi_per:
        with (out / "comparison.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["sample_id", "baseline_tp", "baseline_fp", "baseline_fn",
                        "multi_tp", "multi_fp", "multi_fn"])
            b_by_id = {b["sample_id"]: b for b in baseline_per}
            for m in multi_per:
                sid = m["sample_id"]
                b = b_by_id.get(sid, {})
                w.writerow([sid, b.get("tp", 0), b.get("fp", 0), b.get("fn", 0),
                            m["tp"], m["fp"], m["fn"]])


if __name__ == "__main__":
    main()
