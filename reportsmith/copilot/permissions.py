"""Authority levels, decision confidence, and policy engine for the Copilot."""

from __future__ import annotations

import enum
import logging
from typing import Any

logger = logging.getLogger("orion.core.copilot.permissions")


class AuthorityLevel(enum.StrEnum):
    """Authority levels for the Copilot.

    Each level inherits all abilities of the levels below it.
    """

    OBSERVER = "observer"
    """Can only observe state and generate reports. Never acts."""

    ASSISTANT = "assistant"
    """Can suggest actions and analyze, but never execute."""

    OPERATOR = "operator"
    """Can execute safe tasks (backup, health check, logs)."""

    SENIOR_HUNTER = "senior_hunter"
    """Can validate findings, decide workflow, close reports."""

    ADMINISTRATOR = "admin"
    """Full system configuration access."""

    @classmethod
    def from_str(cls, value: str) -> AuthorityLevel:
        for level in cls:
            if level.value == value:
                return level
            if level.name.lower().replace("_", "") == value.lower().replace("_", ""):
                return level
        logger.warning("Unknown authority level '%s', defaulting to OBSERVER", value)
        return cls.OBSERVER

    def _order_index(self) -> int:
        return list(AuthorityLevel).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, AuthorityLevel):
            return NotImplemented
        return self._order_index() < other._order_index()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, AuthorityLevel):
            return NotImplemented
        return self._order_index() <= other._order_index()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, AuthorityLevel):
            return NotImplemented
        return self._order_index() > other._order_index()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, AuthorityLevel):
            return NotImplemented
        return self._order_index() >= other._order_index()


class DecisionConfidence:
    """Decision Confidence bands — what the Copilot can do at each confidence level.

    Separate from AuthorityLevel: even a Senior Hunter cannot auto-close
    a finding if their confidence is low.
    """

    NO_ACTION = 0.40
    """Below this threshold → no action, recommend human review."""

    REQUEST_APPROVAL = 0.70
    """Between NO_ACTION and this → suggest but request human approval."""

    SAFE_EXECUTE = 0.90
    """Between REQUEST_APPROVAL and this → execute safe tasks autonomously."""

    AUTO_CLOSE = 1.00
    """Above this → can close the full workflow autonomously."""

    @staticmethod
    def band(confidence: float) -> str:
        if confidence < DecisionConfidence.NO_ACTION:
            return "no_action"
        if confidence < DecisionConfidence.REQUEST_APPROVAL:
            return "request_approval"
        if confidence < DecisionConfidence.SAFE_EXECUTE:
            return "safe_execute"
        return "auto_close"

    @staticmethod
    def needs_approval(confidence: float, level: AuthorityLevel) -> bool:
        """Check if a decision at this confidence+authority needs human approval."""
        # Observer/Assistant always need approval
        if level <= AuthorityLevel.ASSISTANT:
            return True
        # Operator
        if level == AuthorityLevel.OPERATOR:
            return confidence < DecisionConfidence.SAFE_EXECUTE
        # Senior Hunter
        if level == AuthorityLevel.SENIOR_HUNTER:
            return confidence < DecisionConfidence.REQUEST_APPROVAL
        # Administrator
        return False


class Policy:
    """A single policy rule."""

    def __init__(
        self,
        name: str,
        description: str,
        level: AuthorityLevel | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self.level = level

    def allows(self, level: AuthorityLevel) -> bool:
        if self.level is None:
            return True
        return level >= self.level


Policies = list[Policy]


class PolicyEngine:
    """Centralized policy engine.

    All safety and operational rules live here, not scattered across modules.
    """

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load built-in safety policies."""
        self.add(
            Policy(
                "auto_report_min_confidence",
                "Nunca reportar automáticamente si confidence < 92%",
                level=AuthorityLevel.SENIOR_HUNTER,
            )
        )
        self.add(
            Policy(
                "never_delete_data",
                "Nunca borrar datos de forma permanente",
                level=AuthorityLevel.ADMINISTRATOR,
            )
        )
        self.add(
            Policy(
                "never_touch_credentials",
                "Nunca tocar credenciales almacenadas",
                level=AuthorityLevel.ADMINISTRATOR,
            )
        )
        self.add(
            Policy(
                "config_read_only",
                "Nunca modificar configuración sin permiso Administrator",
                level=AuthorityLevel.ADMINISTRATOR,
            )
        )
        self.add(
            Policy(
                "safe_mode_only",
                "Nunca ejecutar herramientas fuera del Safe Mode",
                level=AuthorityLevel.OPERATOR,
            )
        )
        self.add(
            Policy(
                "evidence_required",
                "Todo reporte debe incluir evidencia reproducible",
                level=AuthorityLevel.ASSISTANT,
            )
        )

    def add(self, policy: Policy) -> None:
        self._policies[policy.name] = policy
        logger.debug("Policy registered: %s", policy.name)

    def remove(self, name: str) -> bool:
        if name in self._policies:
            del self._policies[name]
            return True
        return False

    def check(self, level: AuthorityLevel, action: str = "", **context: Any) -> list[str]:
        """Check all policies against an action + context.

        Returns a list of policy names that BLOCK the action.
        Empty list = allowed.
        """
        blocked: list[str] = []
        for policy in self._policies.values():
            if not policy.allows(level):
                blocked.append(policy.name)
                logger.debug(
                    "Policy blocks %s: %s (level=%s < required=%s)",
                    action,
                    policy.name,
                    level.value,
                    policy.level.value if policy.level else "any",
                )
        return blocked

    def get_policies(self) -> list[dict]:
        return [
            {"name": p.name, "description": p.description, "min_level": p.level.value if p.level else None}
            for p in self._policies.values()
        ]

    def clear(self) -> None:
        self._policies.clear()
