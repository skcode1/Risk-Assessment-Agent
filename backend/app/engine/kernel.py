"""
Compatibility shim for app.engine.kernel -> app.domain.engine.kernel
"""

from app.domain.engine.kernel import (
    DeterministicRiskScoringKernel,
    KernelExecutionAudit,
    RiskScoringEngineInterface,
    ScoringKernelResult,
)

__all__ = [
    "DeterministicRiskScoringKernel",
    "KernelExecutionAudit",
    "RiskScoringEngineInterface",
    "ScoringKernelResult",
]
