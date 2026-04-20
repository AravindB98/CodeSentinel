"""
REINFORCE policy gradient for evaluator-rejection routing.

When the Evaluator Guardian rejects one or more findings, the graph
normally routes back to the Security Sentinel. But a smarter policy
could route to a specific prompt variant or skip to the Code Quality
Auditor based on the rejection reason. This module learns that policy.

Architecture:
  - State features (one-hot): the set of rejection reasons observed
    (5 reasons total -> 5-dim vector).
  - Actions: which upstream target to route to (N prompt variants of
    Security Sentinel plus "give_up_and_assemble" as an explicit action).
  - Reward: change in approved-finding count after the retry,
    normalized to [-1, 1].

Implementation is intentionally tiny (a 5 x N weight matrix with
softmax). It runs on NumPy by default; a torch variant is available
but not required. Under 500 parameters by design -- too small to
overfit, big enough to learn the 5-reason -> action mapping.

References:
  Williams, R. J. Simple Statistical Gradient-Following Algorithms
  for Connectionist Reinforcement Learning. Machine Learning 8, 1992.
"""
from __future__ import annotations

import json
import logging
import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try numpy; fall back to pure python if not available
try:
    import numpy as np
    HAVE_NUMPY = True
except ImportError:
    HAVE_NUMPY = False

STATE_PATH = Path(__file__).resolve().parent / "policy_state.json"


# --- Feature / action spaces ---

REJECTION_REASONS = (
    "missing_citation",
    "citation_does_not_support",
    "missing_evidence",
    "missing_remediation",
    "schema_violation",
    "internal_contradiction",
    "low_confidence",
)  # 7-dim state vector

ROUTING_ACTIONS = (
    "security_sentinel_default",
    "security_sentinel_strict",
    "security_sentinel_v2",
    "skip_to_assemble",  # give up and deliver the partial report
)


def featurize_rejection_reasons(reasons: List[str]) -> List[float]:
    """One-hot-like encoding over the fixed reason vocabulary."""
    return [1.0 if r in reasons else 0.0 for r in REJECTION_REASONS]


# --- Pure-python linear softmax policy ---

@dataclass
class PolicyState:
    # Weights: len(state) x len(actions) matrix as nested lists
    weights: List[List[float]] = field(default_factory=list)
    # Bias: len(actions) vector
    bias: List[float] = field(default_factory=list)
    # Training history
    total_updates: int = 0
    reward_history: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "weights": self.weights,
            "bias": self.bias,
            "total_updates": self.total_updates,
            "reward_history": self.reward_history[-500:],  # cap history size
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "PolicyState":
        return cls(
            weights=d.get("weights", []),
            bias=d.get("bias", []),
            total_updates=d.get("total_updates", 0),
            reward_history=d.get("reward_history", []),
        )


class ReinforcePolicy:
    """Softmax policy with REINFORCE update rule.

    Exports the same interface regardless of backend (numpy or pure-python).
    """

    def __init__(
        self,
        num_features: int = len(REJECTION_REASONS),
        num_actions: int = len(ROUTING_ACTIONS),
        lr: float = 0.05,
        baseline_decay: float = 0.95,
        state_path: Optional[Path] = None,
        seed: int = 0,
    ):
        self.num_features = num_features
        self.num_actions = num_actions
        self.lr = lr
        self.baseline_decay = baseline_decay
        self.baseline = 0.0
        self.state_path = state_path or STATE_PATH
        self.rng = random.Random(seed)
        self.state = self._load()
        if not self.state.weights:
            # Init small
            self.state.weights = [
                [self._rand_small() for _ in range(num_actions)]
                for _ in range(num_features)
            ]
            self.state.bias = [0.0 for _ in range(num_actions)]

    def _rand_small(self) -> float:
        return (self.rng.random() - 0.5) * 0.1

    # ---- Persistence ----
    def _load(self) -> PolicyState:
        if self.state_path.exists():
            try:
                return PolicyState.from_dict(
                    json.loads(self.state_path.read_text(encoding="utf-8"))
                )
            except Exception as e:
                logger.warning("Could not load policy state (%s); starting fresh", e)
        return PolicyState()

    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps(self.state.to_dict(), indent=2), encoding="utf-8"
        )

    # ---- Forward pass ----
    def logits(self, features: List[float]) -> List[float]:
        """Compute logits = features @ W + b."""
        out = list(self.state.bias)
        for i, fv in enumerate(features):
            if fv == 0.0:
                continue
            row = self.state.weights[i]
            for j in range(self.num_actions):
                out[j] += fv * row[j]
        return out

    @staticmethod
    def softmax(logits: List[float]) -> List[float]:
        m = max(logits)
        exps = [math.exp(x - m) for x in logits]
        s = sum(exps)
        return [e / s for e in exps]

    def act(self, features: List[float], explore: bool = True) -> Tuple[int, List[float]]:
        """Return (action_index, probs). Samples from softmax if explore, else argmax."""
        probs = self.softmax(self.logits(features))
        if not explore:
            return (probs.index(max(probs)), probs)
        # Sample
        r = self.rng.random()
        cum = 0.0
        for i, p in enumerate(probs):
            cum += p
            if r <= cum:
                return (i, probs)
        return (len(probs) - 1, probs)

    # ---- REINFORCE update ----
    def update(
        self,
        features: List[float],
        action: int,
        reward: float,
    ) -> Dict[str, float]:
        """Single-step REINFORCE update with moving-average baseline.

        grad log pi(a|s) w.r.t. logit_j = (1 if a==j else 0) - pi(j|s)
        """
        probs = self.softmax(self.logits(features))
        advantage = reward - self.baseline
        # Update baseline (exponential moving average)
        self.baseline = (
            self.baseline_decay * self.baseline + (1 - self.baseline_decay) * reward
        )

        # d logit_j = advantage * ((j == action) - probs[j])
        for j in range(self.num_actions):
            grad_j = advantage * ((1.0 if j == action else 0.0) - probs[j])
            self.state.bias[j] += self.lr * grad_j
            for i, fv in enumerate(features):
                if fv == 0.0:
                    continue
                self.state.weights[i][j] += self.lr * grad_j * fv

        self.state.total_updates += 1
        self.state.reward_history.append(reward)
        return {
            "advantage": advantage,
            "baseline": self.baseline,
            "probs": probs,
            "total_updates": self.state.total_updates,
        }

    # ---- Inspection ----
    def report(self) -> str:
        lines = [
            "# REINFORCE Policy State",
            f"Total updates: {self.state.total_updates}",
            f"Baseline: {self.baseline:.3f}",
        ]
        if self.state.reward_history:
            last = self.state.reward_history[-50:]
            avg_last = sum(last) / len(last)
            lines.append(f"Avg reward (last 50): {avg_last:.3f}")
        lines.append("\n## Action preferences by rejection reason (softmax scores)")
        for i, reason in enumerate(REJECTION_REASONS):
            features = [1.0 if k == i else 0.0 for k in range(self.num_features)]
            probs = self.softmax(self.logits(features))
            best_i = probs.index(max(probs))
            best_action = ROUTING_ACTIONS[best_i]
            prob_str = ", ".join(f"{a}={p:.2f}" for a, p in zip(ROUTING_ACTIONS, probs))
            lines.append(f"  {reason:30s} -> {best_action}  ({prob_str})")
        return "\n".join(lines)


def get_policy() -> ReinforcePolicy:
    """Singleton-ish factory."""
    return ReinforcePolicy()


if __name__ == "__main__":
    # Quick demo: learn that "missing_citation" should route to strict,
    # and "missing_remediation" should route to v2, via synthetic rewards.
    rng = random.Random(11)
    policy = ReinforcePolicy(
        state_path=STATE_PATH.with_name("policy_demo.json"),
        seed=11,
    )

    def ground_truth_reward(reason: str, action_name: str) -> float:
        best = {
            "missing_citation": "security_sentinel_strict",
            "citation_does_not_support": "security_sentinel_strict",
            "missing_evidence": "security_sentinel_v2",
            "missing_remediation": "security_sentinel_v2",
            "schema_violation": "security_sentinel_default",
            "internal_contradiction": "skip_to_assemble",
            "low_confidence": "security_sentinel_default",
        }
        if action_name == best[reason]:
            return 1.0 + rng.gauss(0, 0.05)
        return 0.1 + rng.gauss(0, 0.05)

    for t in range(600):
        reason = rng.choice(REJECTION_REASONS)
        features = featurize_rejection_reasons([reason])
        action_idx, _ = policy.act(features)
        action_name = ROUTING_ACTIONS[action_idx]
        r = max(-1.0, min(1.5, ground_truth_reward(reason, action_name)))
        policy.update(features, action_idx, r)

    print(policy.report())
