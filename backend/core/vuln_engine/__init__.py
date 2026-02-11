from backend.core.vuln_engine.registry import VulnerabilityRegistry
from backend.core.vuln_engine.payload_generator import PayloadGenerator


def __getattr__(name):
    """Lazy import for DynamicVulnerabilityEngine (requires database models)"""
    if name == "DynamicVulnerabilityEngine":
        from backend.core.vuln_engine.engine import DynamicVulnerabilityEngine
        return DynamicVulnerabilityEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["DynamicVulnerabilityEngine", "VulnerabilityRegistry", "PayloadGenerator"]
