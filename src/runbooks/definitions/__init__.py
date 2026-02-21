"""
Runbooks package - Automated remediation scripts.

All runbooks must be registered in the registry to be executed.
This provides security through an allowlist approach.
"""

# Import all runbooks to register them
from src.runbooks.definitions import cleanup_disk, health_check, restart_service
from src.runbooks.registry import registry, runbook

__all__ = ["registry", "runbook", "restart_service", "cleanup_disk", "health_check"]
