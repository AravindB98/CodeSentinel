"""
UCB-1 contextual bandit for prompt variant selection.

Each agent has multiple prompt variants (tuned manually on a held-out set).
This module learns, at inference time, which variant performs best under
which input context. The bandit receives a binary reward from the
Evaluator Guardian (1 if finding approved on first pass, 0 otherwise)
and converges toward the best variant per context bucket.

The context vector is discretized into buckets by:
  - detected language (python | javascript | java | unknown)
  - input complexity class (short | medium | long, by token count)
  - apparent vulnerability class (injection | deserialization | auth |
    crypto | other, inferred from retrieved passages)

Context space = 4 x 3 x 5 = 60 buckets. Per-bucket UCB-1 is tractable
and avoids the need for a neural function approximator.

References:
  Auer, Cesa-Bianchi, Fischer. Finite-time Analysis of the Multiarmed
  Bandit Problem. Machine Learning 47, 2002.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

STATE_PATH = Path(__file__).resolve().parent / "bandit_state.json"


# --- Context bucketing ---

LANGUAGES = ("python", "javascript", "java", "unknown")
COMPLEXITY = ("short", "medium", "long")
VULN_CLASSES = ("injection", "deserialization", "auth", "crypto", "other")


def complexity_bucket(code: str) -> str:
    n = len(code)
    if n < 400:
        return "short"
    if n < 1600:
        return "medium"
    return "long"


def infer_vuln_class(retrieved_passage_ids: List[str]) -> str:
    """Coarse classification by prefix of top retrieved passage."""
    ids_str = " ".join(retrieved_passage_ids).lower()
    if any(k in ids_str for k in ("cwe-89", "cwe-78", "cwe-94", "cwe-79", "cwe-77", "py-01",
                                    "py-03", "py-04", "js-01", "js-02", "js-04", "js-05",
                                    "java-01", "java-03", "a03")):
        return "injection"
    if any(k in ids_str for k in ("cwe-502", "py-02", "py-07", "java-02", "a08")):
        return "deserialization"
    if any(k in ids_str for k in ("cwe-287", "cwe-384", "cwe-521", "cwe-798", "py-05", "a07")):
        return "auth"
    if any(k in ids_str for k in ("cwe-295", "cwe-327", "cwe-311", "py-06", "py-08", "a02")):
        return "crypto"
    return "other"


def encode_context(language: str, code: str, retrieved_passage_ids: List[str]) -> str:
    lang = language if language in LANGUAGES else "unknown"
    comp = complexity_bucket(code)
    vclass = infer_vuln_class(retrieved_passage_ids)
    return f"{lang}|{comp}|{vclass}"


# --- UCB-1 core ---

@dataclass
class ArmStats:
    """Per-arm statistics: total reward and pull count."""
    pulls: int = 0
    reward_sum: float = 0.0

    def mean(self) -> float:
        return self.reward_sum / self.pulls if self.pulls > 0 else 0.0


@dataclass
class BanditState:
    """Per-context, per-arm UCB-1 state."""
    # Keyed by context bucket string -> arm name -> ArmStats
    stats: Dict[str, Dict[str, ArmStats]] = field(default_factory=dict)
    # Running global pull count per context (for the confidence term)
    context_pulls: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "stats": {
                ctx: {arm: {"pulls": s.pulls, "reward_sum": s.reward_sum}
                      for arm, s in arms.items()}
                for ctx, arms in self.stats.items()
            },
            "context_pulls": self.context_pulls,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "BanditState":
        state = cls()
        state.context_pulls = dict(d.get("context_pulls", {}))
        for ctx, arms in d.get("stats", {}).items():
            state.stats[ctx] = {
                arm: ArmStats(pulls=s["pulls"], reward_sum=s["reward_sum"])
                for arm, s in arms.items()
            }
        return state


class UCB1Bandit:
    """Contextual UCB-1 bandit with one independent bandit per context bucket.

    Exploration constant c controls the width of the UCB confidence interval.
    Default c = sqrt(2) is the textbook value; we anneal it toward 0 as
    pulls accumulate so exploration tapers off.
    """

    def __init__(
        self,
        arms: Tuple[str, ...],
        c_initial: float = 1.414,
        c_min: float = 0.1,
        anneal_after: int = 50,
        state_path: Optional[Path] = None,
    ):
        self.arms = arms
        self.c_initial = c_initial
        self.c_min = c_min
        self.anneal_after = anneal_after
        self.state_path = state_path or STATE_PATH
        self.state = self._load()

    # ---- Persistence ----
    def _load(self) -> BanditState:
        if self.state_path.exists():
            try:
                return BanditState.from_dict(
                    json.loads(self.state_path.read_text(encoding="utf-8"))
                )
            except Exception as e:
                logger.warning("Could not load bandit state (%s); starting fresh", e)
        return BanditState()

    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(self.state.to_dict(), indent=2), encoding="utf-8"
        )

    # ---- Core interface ----
    def _ensure_context(self, ctx: str) -> Dict[str, ArmStats]:
        if ctx not in self.state.stats:
            self.state.stats[ctx] = {arm: ArmStats() for arm in self.arms}
        if ctx not in self.state.context_pulls:
            self.state.context_pulls[ctx] = 0
        return self.state.stats[ctx]

    def _exploration_c(self, ctx: str) -> float:
        pulls = self.state.context_pulls.get(ctx, 0)
        if pulls <= self.anneal_after:
            return self.c_initial
        # Linear anneal toward c_min
        factor = max(0.0, 1.0 - (pulls - self.anneal_after) / (self.anneal_after * 2))
        return self.c_min + factor * (self.c_initial - self.c_min)

    def select(self, ctx: str) -> str:
        """Pick an arm for the given context via UCB-1. Always explores
        each arm at least once per context before going greedy.

        Returns the chosen arm name.
        """
        arms = self._ensure_context(ctx)

        # Pull any unexplored arm first
        for arm_name, arm in arms.items():
            if arm.pulls == 0:
                return arm_name

        total = self.state.context_pulls[ctx]
        c = self._exploration_c(ctx)
        log_total = math.log(max(1, total))

        best_arm = None
        best_score = -float("inf")
        for arm_name, arm in arms.items():
            conf = c * math.sqrt(log_total / arm.pulls)
            score = arm.mean() + conf
            if score > best_score:
                best_score = score
                best_arm = arm_name
        assert best_arm is not None
        return best_arm

    def update(self, ctx: str, arm: str, reward: float) -> None:
        """Record a reward for the chosen arm. Reward should be in [0, 1]."""
        arms = self._ensure_context(ctx)
        if arm not in arms:
            logger.warning("Unknown arm '%s' for context '%s'; ignoring", arm, ctx)
            return
        arms[arm].pulls += 1
        arms[arm].reward_sum += float(reward)
        self.state.context_pulls[ctx] += 1

    # ---- Inspection ----
    def report(self) -> str:
        """Human-readable summary of the current bandit state."""
        lines = ["# UCB-1 Bandit State"]
        for ctx, arms in sorted(self.state.stats.items()):
            total = self.state.context_pulls.get(ctx, 0)
            lines.append(f"\n## Context: {ctx}  (total pulls: {total})")
            for arm_name, arm in arms.items():
                lines.append(
                    f"  - {arm_name}: pulls={arm.pulls}, mean_reward={arm.mean():.3f}"
                )
        return "\n".join(lines)


# --- Convenience: prompt variants ---

# Define the prompt variants each agent has. At integration time, each
# agent loads the selected variant from graph/prompts/<name>.md.
PROMPT_VARIANTS: Dict[str, Tuple[str, ...]] = {
    "security_sentinel": ("security", "security_v2", "security_strict"),
    "code_quality_auditor": ("quality", "quality_concise"),
    "evaluator_guardian": ("evaluator", "evaluator_strict"),
}


def get_bandit(agent_name: str) -> UCB1Bandit:
    """Factory: return the bandit for a specific agent's prompt selection."""
    arms = PROMPT_VARIANTS.get(agent_name, ("default",))
    path = STATE_PATH.with_name(f"bandit_{agent_name}.json")
    return UCB1Bandit(arms=arms, state_path=path)


if __name__ == "__main__":
    # Quick demo: simulate 200 rounds on a synthetic reward surface.
    import random
    rng = random.Random(7)

    # Synthetic true best-arm-per-context table
    truth = {
        "python|short|injection": "security_strict",
        "python|medium|injection": "security_v2",
        "python|long|injection": "security",
        "python|short|deserialization": "security_strict",
        "javascript|short|injection": "security_v2",
    }
    b = UCB1Bandit(
        arms=("security", "security_v2", "security_strict"),
        state_path=STATE_PATH.with_name("bandit_demo.json"),
    )
    contexts = list(truth.keys())
    regret = 0.0
    for t in range(200):
        ctx = rng.choice(contexts)
        arm = b.select(ctx)
        # Reward: 0.85 for best, 0.55 otherwise, with noise
        r = (0.85 if arm == truth[ctx] else 0.55) + rng.gauss(0, 0.08)
        r = max(0.0, min(1.0, r))
        b.update(ctx, arm, r)
        regret += (0.85 - r)
    print(b.report())
    print(f"\nTotal regret over 200 rounds: {regret:.2f}")
