"""
Synthetic data verifier.

Takes a synthetic suite produced by synth.generate and verifies each
sample independently:

1. Vulnerable samples must be flagged by at least one regex-based detector
   matching the claimed CWE.
2. Safe variants must NOT be flagged by those detectors.

The verifier has NO access to the generator's prompt or its internal
explanation, which is the separation that prevents the generator from
gaming the verifier. This is computational skepticism in practice.

Samples that fail verification are removed from the output suite and
written to a separate rejected.json for inspection.

Usage:
    python -m synth.verify eval/datasets/synthetic_suite.json
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)s  %(message)s")
logger = logging.getLogger(__name__)


# Independent detection rules. Intentionally simpler than the Security Sentinel
# to keep the verifier a truly independent signal.
DETECTORS: Dict[str, List[re.Pattern]] = {
    "CWE-89": [
        re.compile(r'execute\s*\(\s*f["\']'),
        re.compile(r'\.query\s*\(\s*`[^`]*\$\{'),
        re.compile(r'executeQuery\s*\([^)]*\+'),
        re.compile(r'\.format\s*\([^)]*\)\s*\)'),
    ],
    "CWE-502": [
        re.compile(r'pickle\.loads?\s*\('),
        re.compile(r'ObjectInputStream'),
        re.compile(r'yaml\.load\s*\([^)]*\)(?!.*SafeLoader)(?!.*safe_load)', re.DOTALL),
    ],
    "CWE-78": [
        re.compile(r'shell\s*=\s*True'),
        re.compile(r'child_process\.exec\s*\('),
        re.compile(r'\bexec\s*\(`[^`]*\$\{'),
        re.compile(r'Runtime\.getRuntime\(\)\.exec'),
    ],
    "CWE-94": [
        re.compile(r'\beval\s*\('),
    ],
    "CWE-79": [
        re.compile(r'\.innerHTML\s*='),
        re.compile(r'dangerouslySetInnerHTML'),
    ],
    "CWE-295": [
        re.compile(r'verify\s*=\s*False'),
    ],
    "CWE-327": [
        re.compile(r'hashlib\.(md5|sha1)\s*\('),
        re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"'),
    ],
    "CWE-798": [
        re.compile(r'(api_key|password|secret|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']',
                   re.IGNORECASE),
    ],
    "CWE-611": [
        re.compile(r'DocumentBuilderFactory\.newInstance\(\)(?!.*disallow-doctype-decl)',
                   re.DOTALL),
    ],
    "CWE-22": [
        re.compile(r'send_file\s*\(\s*f?["\'][^"\']*\{'),
        re.compile(r'open\s*\(\s*f?["\'][^"\']*\{'),
    ],
    "CWE-915": [
        re.compile(r'Object\.assign\s*\([^,]+,\s*req'),
        re.compile(r'\.\.\.req\.body'),
    ],
}


def detect_cwe(code: str, cwe_id: str) -> bool:
    """Return True if at least one detector for cwe_id matches the code."""
    detectors = DETECTORS.get(cwe_id, [])
    return any(d.search(code) for d in detectors)


def any_cwe_matches(code: str) -> List[str]:
    """Return the list of CWE IDs whose detectors fire on the code."""
    return [cwe for cwe, ds in DETECTORS.items() if any(d.search(code) for d in ds)]


def verify_sample(sample: Dict) -> Tuple[bool, str]:
    """Verify one sample. Returns (passed, reason_if_failed)."""
    code = sample["code"]
    gt = sample.get("ground_truth", [])

    if gt:
        # Vulnerable sample: its claimed CWE must be detected.
        for entry in gt:
            cwe = entry["cwe_id"]
            if cwe not in DETECTORS:
                return False, f"no detector available for claimed CWE {cwe}"
            if not detect_cwe(code, cwe):
                return False, f"claimed {cwe} but no detector matched"
        return True, "verified"
    else:
        # Safe variant: no detectors should fire. One permitted exception is
        # the ALLOWED-list pattern for CWE-915, which is the SAFE version.
        hits = any_cwe_matches(code)
        if hits:
            return False, f"safe variant but detectors fired for: {hits}"
        return True, "verified_clean"


def verify_suite(in_path: Path, out_path: Path, rejected_path: Path) -> Dict:
    """Verify every sample. Write passing samples to out_path, rejected to rejected_path."""
    payload = json.loads(in_path.read_text(encoding="utf-8"))
    samples = payload.get("samples", [])

    passed, rejected = [], []
    for s in samples:
        ok, reason = verify_sample(s)
        if ok:
            passed.append(s)
        else:
            s_copy = dict(s)
            s_copy["rejection_reason"] = reason
            rejected.append(s_copy)
            logger.warning("REJECT %s: %s", s["sample_id"], reason)

    out_path.write_text(json.dumps({
        "version": payload.get("version", "1.0"),
        "description": "Verified synthetic samples.",
        "samples": passed,
    }, indent=2), encoding="utf-8")

    if rejected:
        rejected_path.write_text(json.dumps({
            "samples": rejected,
        }, indent=2), encoding="utf-8")

    return {
        "total": len(samples),
        "passed": len(passed),
        "rejected": len(rejected),
        "rejection_rate": round(len(rejected) / max(1, len(samples)), 3),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="synthetic_suite.json to verify")
    parser.add_argument("--out", default=None, help="verified output (default overwrites input)")
    parser.add_argument("--rejected", default="eval/datasets/synthetic_rejected.json")
    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.out) if args.out else in_path
    rejected_path = Path(args.rejected)

    result = verify_suite(in_path, out_path, rejected_path)
    logger.info("Verification complete: %d/%d passed (rejection_rate=%.1f%%)",
                result["passed"], result["total"], 100 * result["rejection_rate"])
    logger.info("Verified suite: %s", out_path)
    if result["rejected"] > 0:
        logger.info("Rejected samples: %s", rejected_path)


if __name__ == "__main__":
    main()
