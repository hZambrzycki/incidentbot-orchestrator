"""
Runbook Registry - Allowlist of permitted runbooks.
Defines which runbooks can be executed and their constraints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from src.core.config import settings
from src.core.models import RunbookDefinition, Severity

RunbookHandler = Callable[..., Awaitable[dict[str, Any]]]


@dataclass
class RunbookConfig:
    """Configuration for a registered runbook."""

    name: str
    description: str
    handler: RunbookHandler
    category: str = "general"
    severity_threshold: Severity = Severity.WARNING
    auto_execute: bool = True
    requires_confirmation: bool = False
    timeout: int = 300
    allowed_services: list[str] = field(default_factory=lambda: ["*"])
    allowed_parameters: list[str] = field(default_factory=list)
    dangerous: bool = False


class RunbookRegistry:
    """
    Central registry for all allowed runbooks.

    Security features:
    - Only registered runbooks can be executed
    - Service targeting restrictions
    - Parameter validation
    - Confirmation requirements for dangerous operations
    """

    def __init__(self) -> None:
        self._runbooks: dict[str, RunbookConfig] = {}

    def register(
        self,
        name: str,
        description: str,
        handler: RunbookHandler,
        category: str = "general",
        severity_threshold: Severity = Severity.WARNING,
        auto_execute: bool = True,
        requires_confirmation: bool = False,
        timeout: int = 300,
        allowed_services: Optional[list[str]] = None,
        allowed_parameters: Optional[list[str]] = None,
        dangerous: bool = False,
    ) -> None:
        """Register a runbook in the allowlist."""
        self._runbooks[name] = RunbookConfig(
            name=name,
            description=description,
            handler=handler,
            category=category,
            severity_threshold=severity_threshold,
            auto_execute=auto_execute,
            requires_confirmation=requires_confirmation,
            timeout=timeout,
            allowed_services=allowed_services or ["*"],
            allowed_parameters=allowed_parameters or [],
            dangerous=dangerous,
        )

    def get(self, name: str) -> Optional[RunbookConfig]:
        """Get a registered runbook by name."""
        return self._runbooks.get(name)

    def is_allowed(self, name: str) -> bool:
        """Check if a runbook is in the allowlist."""
        return name in self._runbooks

    def can_target_service(self, runbook_name: str, service: str) -> bool:
        """Check if a runbook is allowed to target a specific service."""
        config = self._runbooks.get(runbook_name)
        if not config:
            return False

        svc = (service or "").strip().lower()
        if not svc:
            return False

        # 1) Global allowlist (if configured)
        allowed_global = settings.allowed_target_services_set

        # Treat None or empty set as "no restriction"
        if allowed_global:
            if "*" not in allowed_global and svc not in allowed_global:
                return False

        # 2) Runbook-level allowlist
        if "*" in (config.allowed_services or []):
            return True

        allowed_rb = {
            (s or "").strip().lower() for s in (config.allowed_services or [])
        }
        allowed_rb.discard("")
        return svc in allowed_rb

    def can_auto_execute(self, runbook_name: str, severity: Severity) -> bool:
        """Check if a runbook can be auto-executed for a given severity."""
        config = self._runbooks.get(runbook_name)
        if not config or not config.auto_execute:
            return False
        return severity >= config.severity_threshold

    def validate_parameters(
        self, runbook_name: str, params: dict[str, object] | None
    ) -> Optional[str]:
        """Validate that only allowed parameters are provided for a runbook."""
        config = self._runbooks.get(runbook_name)
        if not config:
            return f"Runbook '{runbook_name}' is not registered"

        params = params or {}

        # Policy: if allowed_parameters is empty => no restriction
        if not config.allowed_parameters:
            return None

        extra = set(params.keys()) - set(config.allowed_parameters)
        if extra:
            return f"Invalid parameters for '{runbook_name}': {sorted(extra)}"

        return None

    def list_runbooks(self, category: Optional[str] = None) -> list[RunbookConfig]:
        """List all registered runbooks, optionally filtered by category."""
        runbooks = list(self._runbooks.values())
        if category:
            runbooks = [r for r in runbooks if r.category == category]
        return runbooks

    def to_definitions(self) -> list[RunbookDefinition]:
        """Convert all registered runbooks to RunbookDefinition models."""
        return [
            RunbookDefinition(
                name=config.name,
                description=config.description,
                category=config.category,
                severity_threshold=config.severity_threshold,
                auto_execute=config.auto_execute,
                requires_confirmation=config.requires_confirmation,
                timeout=config.timeout,
                allowed_services=config.allowed_services,
                parameters={
                    "allowed_parameters": list(config.allowed_parameters or [])
                },
            )
            for config in self._runbooks.values()
        ]


# Global registry instance
registry = RunbookRegistry()


def runbook(
    name: str,
    description: str,
    category: str = "general",
    severity_threshold: Severity = Severity.WARNING,
    auto_execute: bool = True,
    requires_confirmation: bool = False,
    timeout: int = 300,
    allowed_services: list[str] | None = None,
    allowed_parameters: list[str] | None = None,
    dangerous: bool = False,
):
    """Decorator to register a function as a runbook."""

    def decorator(func: RunbookHandler):
        registry.register(
            name=name,
            description=description,
            handler=func,
            category=category,
            severity_threshold=severity_threshold,
            auto_execute=auto_execute,
            requires_confirmation=requires_confirmation,
            timeout=timeout,
            allowed_services=allowed_services,
            allowed_parameters=allowed_parameters,
            dangerous=dangerous,
        )
        return func

    return decorator
