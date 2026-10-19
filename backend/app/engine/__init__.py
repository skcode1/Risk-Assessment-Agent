"""
Compatibility shim for app.engine -> app.domain.engine
Provides backwards compatibility for imports expecting app.engine.* modules.
"""

from app.domain.engine import calculators, invariants, kernel, resolver

__all__ = [
    "calculators",
    "invariants",
    "kernel",
    "resolver",
]

# Re-export key classes for direct imports
from app.domain.engine.invariants import (
    InvariantRuleConfig,
    InvariantViolationError,
    ScoringInvariantVerifier,
)
from app.domain.engine.kernel import DeterministicRiskScoringKernel, ScoringKernelResult
from app.domain.engine.resolver import DynamicRiskCategoryResolver

__all__.extend([
    "DeterministicRiskScoringKernel",
    "DynamicRiskCategoryResolver",
    "InvariantRuleConfig",
    "InvariantViolationError",
    "ScoringInvariantVerifier",
    "ScoringKernelResult",
])