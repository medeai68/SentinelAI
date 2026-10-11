"""Configurable response policy (Part 7).

Maps a DetectionResult to a RECOMMENDED response action. The policy is
pure decision logic — it never performs anything.

Thresholds (no arbitrary numbers invented):

  * detection threshold = 0.50 — the XGBoost threshold validated in the
    Part 6 threshold analysis (both the selected final test threshold and
    the training-only best-F1 threshold were 0.50).
  * high-confidence threshold = detection_config.HIGH_ATTACK_PROBABILITY
    (0.8) — the existing, documented severity threshold, reused rather
    than re-invented.

Decision rule (configurable):

    attack probability below the detection threshold  -> NO_ACTION
    ATTACK, below high confidence                     -> ALERT_ONLY
    high-confidence ATTACK, DRY_RUN mode              -> DRY_RUN_BLOCK (simulated)
    high-confidence ATTACK, AUTHORIZED mode           -> BLOCK_REQUESTED
                                                         (only with an adapter)

"Detected attack" is NOT "blocked": in the default DRY_RUN mode nothing
is ever blocked — the higher-confidence action is simulated and logged.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import detection_config as dcfg
from src.response.actions import (
    ACTION_ALERT_ONLY,
    ACTION_BLOCK_REQUESTED,
    ACTION_DRY_RUN_BLOCK,
    ACTION_NO_ACTION,
    DEFAULT_RESPONSE_MODE,
    MODE_AUTHORIZED,
    RESPONSE_MODES,
)

# Part 6-validated XGBoost decision threshold (see reports/threshold_analysis.csv)
XGBOOST_VALIDATED_THRESHOLD = 0.50


@dataclass(frozen=True)
class ResponsePolicy:
    """Explicit, configurable response policy."""

    mode: str = DEFAULT_RESPONSE_MODE
    detection_threshold: float = XGBOOST_VALIDATED_THRESHOLD
    high_confidence_threshold: float = dcfg.HIGH_ATTACK_PROBABILITY

    def __post_init__(self) -> None:
        if self.mode not in RESPONSE_MODES:
            raise ValueError(f"Unknown response mode: {self.mode!r} (expected {RESPONSE_MODES})")
        for name, value in (
            ("detection_threshold", self.detection_threshold),
            ("high_confidence_threshold", self.high_confidence_threshold),
        ):
            if not 0.0 <= float(value) <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1, got {value}")
        if self.high_confidence_threshold < self.detection_threshold:
            raise ValueError(
                "high_confidence_threshold must be >= detection_threshold "
                f"({self.high_confidence_threshold} < {self.detection_threshold})"
            )

    def recommend(self, detection) -> tuple[str, str]:
        """Return (action, reason) for one successful DetectionResult.

        Callers must handle non-successful detections before calling this
        (ResponseEngine does — those are reported as SKIPPED/NO_ACTION).
        """
        probability = detection.attack_probability
        if probability is None:
            # No probability available: rely on the model's predicted class.
            is_attack = detection.prediction == 1
            probability_text = "probability unavailable"
        else:
            is_attack = probability >= self.detection_threshold
            probability_text = f"attack probability {probability:.4f}"

        if not is_attack:
            return (
                ACTION_NO_ACTION,
                f"{probability_text} below the detection threshold "
                f"{self.detection_threshold:.2f} (validated XGBoost threshold)",
            )

        if probability is not None and probability >= self.high_confidence_threshold:
            if self.mode == MODE_AUTHORIZED:
                return (
                    ACTION_BLOCK_REQUESTED,
                    f"high-confidence attack ({probability_text} >= "
                    f"{self.high_confidence_threshold:.2f}) — authorized adapter requested",
                )
            return (
                ACTION_DRY_RUN_BLOCK,
                f"high-confidence attack ({probability_text} >= "
                f"{self.high_confidence_threshold:.2f}) — simulated block "
                "(DRY_RUN mode: no firewall/network change was made)",
            )

        return (
            ACTION_ALERT_ONLY,
            f"attack detected ({probability_text}) below the high-confidence "
            f"threshold {self.high_confidence_threshold:.2f} — alert only",
        )


#: Default policy: DRY_RUN, Part 6-validated thresholds.
DEFAULT_POLICY = ResponsePolicy()
