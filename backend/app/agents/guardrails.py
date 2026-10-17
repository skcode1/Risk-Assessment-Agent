"""
Post-Generation Guardrail Verification Engine for Explainable AI (XAI).
Enforces absolute mathematical and categorical invariance on LLM completions:
  1. Validates strict JSON syntax and schema completeness.
  2. Parses and verifies that no hallucinated or mutated risk score exists.
  3. Rejects any completion contradicting the deterministic score or category rating.
  4. Detects and flags prompt injection leakage or prohibited advisory keywords.
"""

from dataclasses import dataclass, field
from decimal import Decimal
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Union

from app.core.telemetry import get_tracer
from app.domain.models.enums import ComponentDriver, RiskCategory

logger = logging.getLogger(__name__)
tracer = get_tracer()


@dataclass(frozen=True)
class GuardrailEvaluationResult:
    """Immutable audit outcome of the guardrail verification pipeline."""

    passed: bool
    parsed_payload: Optional[Dict[str, Any]] = None
    violation_reason: Optional[str] = None
    checks_evaluated: Dict[str, bool] = field(default_factory=dict)
    detected_score_mentions: List[str] = field(default_factory=list)


class LLMGuardrailEnforcer:
    """
    Enforces deterministic safety invariants and lexical boundaries on unstructured
    or structured LLM outputs, ensuring the model never tampers with calculated scores.
    """

    # Regex detecting numeric patterns commonly formatted as risk scores (e.g., 78.4, 78.4/100, 78%)
    _SCORE_REGEX = re.compile(
        r"(?:score|rating|evaluated(?:\s+to)?|risk)\s*(?:of|is|was|:)?\s*([0-9]{1,3}(?:\.[0-9]{1,2})?)",
        re.IGNORECASE,
    )

    # Keywords signaling unauthorized score recalculations or modifications
    _TAMPER_PATTERNS = [
        re.compile(r"adjust(?:ed|ing)?\s+the\s+score\s+to", re.IGNORECASE),
        re.compile(r"recalculated\s+(?:the\s+)?(?:score|rating)\s+(?:as|to)", re.IGNORECASE),
        re.compile(r"should\s+be\s+(?:downgraded|upgraded|changed)\s+to", re.IGNORECASE),
        re.compile(r"actual\s+risk\s+is\s+closer\s+to", re.IGNORECASE),
        re.compile(r"override\s+the\s+deterministic\s+score", re.IGNORECASE),
    ]

    # Required JSON schema keys
    _REQUIRED_SCHEMA_KEYS: Set[str] = {
        "summary_narrative",
        "primary_driver",
        "key_factors",
        "evidence_citations",
    }

    def __init__(self, score_tolerance: Decimal = Decimal("0.0")) -> None:
        # Zero tolerance: deterministic mathematical baseline must match exactly
        self.score_tolerance = score_tolerance

    def verify(
        self,
        raw_response: str,
        baseline_score: Union[Decimal, float, str],
        baseline_rating: Union[RiskCategory, str],
    ) -> GuardrailEvaluationResult:
        """
        Executes end-to-end invariant validation on the raw LLM completion string:
          1. Cleans Markdown fencing artifacts.
          2. Validates JSON syntax and schema completeness.
          3. Asserts the primary driver is a recognized component.
          4. Verifies narrative claims against score and category invariance.
          5. Scans for adversarial tamper instructions.
        """
        with tracer.start_as_current_span("guardrails.verify") as span:
            span.set_attribute("baseline_score", str(baseline_score))
            span.set_attribute("baseline_rating", str(baseline_rating))

            checks: Dict[str, bool] = {
                "json_syntax_valid": False,
                "schema_keys_complete": False,
                "primary_driver_valid": False,
                "tamper_patterns_absent": False,
                "score_invariance_maintained": False,
                "rating_invariance_maintained": False,
            }

            # 1. Clean Markdown code fences if the model emitted any
            cleaned_payload = self._clean_raw_text(raw_response)

            # 2. Parse JSON
            try:
                parsed_data = json.loads(cleaned_payload)
                if not isinstance(parsed_data, dict):
                    return self._failure("Parsed response is not a valid JSON dictionary", checks)
                checks["json_syntax_valid"] = True
            except json.JSONDecodeError as jde:
                logger.warning("Guardrail JSON parsing failure: %s", jde)
                return self._failure(f"Malformed JSON response: {jde}", checks)

            # 3. Verify Required Top-Level Keys
            missing_keys = self._REQUIRED_SCHEMA_KEYS - set(parsed_data.keys())
            if missing_keys:
                return self._failure(
                    f"Response missing required keys: {sorted(missing_keys)}",
                    checks,
                )
            checks["schema_keys_complete"] = True

            # 4. Verify Primary Driver Enumeration
            raw_driver = str(parsed_data.get("primary_driver", "")).strip().upper()
            valid_drivers = {d.value for d in ComponentDriver}
            if raw_driver not in valid_drivers:
                return self._failure(
                    f"Invalid primary_driver '{raw_driver}'. Must be one of: {sorted(valid_drivers)}",
                    checks,
                )
            checks["primary_driver_valid"] = True

            # 5. Check Prohibited Tamper / Recalculation Patterns
            combined_text = (
                f"{parsed_data.get('summary_narrative', '')} "
                f"{' '.join(str(f) for f in parsed_data.get('key_factors', []))}"
            )

            for pattern in self._TAMPER_PATTERNS:
                if pattern.search(combined_text):
                    return self._failure(
                        f"Detected prohibited score tampering/modification phrasing: '{pattern.pattern}'",
                        checks,
                    )
            checks["tamper_patterns_absent"] = True

            # 6. Verify Score Invariance
            expected_score_dec = Decimal(str(baseline_score)).quantize(Decimal("0.1"))
            detected_scores: List[str] = []

            for match in self._SCORE_REGEX.finditer(combined_text):
                score_str = match.group(1)
                detected_scores.append(score_str)
                try:
                    found_score_dec = Decimal(score_str).quantize(Decimal("0.1"))
                    # If the text explicitly cites a score, it must not contradict the baseline
                    if abs(found_score_dec - expected_score_dec) > self.score_tolerance:
                        return self._failure(
                            f"Discrepancy detected: narrative references score {found_score_dec}, "
                            f"which contradicts the deterministic baseline {expected_score_dec}.",
                            checks,
                            detected_scores=detected_scores,
                        )
                except Exception:
                    continue

            checks["score_invariance_maintained"] = True

            # 7. Verify Categorical Rating Invariance
            expected_rating_str = (
                baseline_rating.value if isinstance(baseline_rating, RiskCategory) else str(baseline_rating)
            ).upper()

            # Ensure contradictory rating labels are not asserted as the actual rating
            all_ratings = {r.value for r in RiskCategory}
            conflicting_ratings = all_ratings - {expected_rating_str}

            for conflict in conflicting_ratings:
                conflict_pattern = re.compile(
                    rf"\b(?:rated|rating|classified(?:\s+as)?)\s*(?:is|as|was|:)?\s*{re.escape(conflict)}\b",
                    re.IGNORECASE,
                )
                if conflict_pattern.search(combined_text):
                    return self._failure(
                        f"Categorical rating contradiction: narrative declared rating '{conflict}', "
                        f"which conflicts with baseline rating '{expected_rating_str}'.",
                        checks,
                        detected_scores=detected_scores,
                    )

            checks["rating_invariance_maintained"] = True

            return GuardrailEvaluationResult(
                passed=True,
                parsed_payload=parsed_data,
                checks_evaluated=checks,
                detected_score_mentions=detected_scores,
            )

    @staticmethod
    def _clean_raw_text(raw_text: str) -> str:
        """Strips markdown delimiters, whitespace, and leading formatting artifacts."""
        cleaned = raw_text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[len("```json") :].strip()
        elif cleaned.startswith("```"):
            cleaned = cleaned[len("```") :].strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
        return cleaned

    @staticmethod
    def _failure(
        reason: str,
        checks: Dict[str, bool],
        detected_scores: Optional[List[str]] = None,
    ) -> GuardrailEvaluationResult:
        """Constructs a failed evaluation audit container."""
        return GuardrailEvaluationResult(
            passed=False,
            parsed_payload=None,
            violation_reason=reason,
            checks_evaluated=checks,
            detected_score_mentions=detected_scores or [],
        )