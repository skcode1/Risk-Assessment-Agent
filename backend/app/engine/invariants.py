"""
Compatibility shim for app.engine.invariants -> app.domain.engine.invariants
"""

from app.domain.engine.invariants import (
    InvariantRuleConfig,
    InvariantViolationError,
    ScoringInvariantVerifier,
)

__all__ = [
    "InvariantRuleConfig",
    "InvariantViolationError",
    "ScoringInvariantVerifier",
]