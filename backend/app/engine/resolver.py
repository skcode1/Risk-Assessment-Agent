"""
Compatibility shim for app.engine.resolver -> app.domain.engine.resolver
"""

from app.domain.engine.resolver import DynamicRiskCategoryResolver

__all__ = [
    "DynamicRiskCategoryResolver",
]