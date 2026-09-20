"""Context Builder — gathers all information before the Copilot analyzes."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from reportsmith.copilot.config import CopilotConfig
from reportsmith.copilot.permissions import AuthorityLevel, DecisionConfidence

logger = logging.getLogger("orion.core.copilot.context")


class CopilotContext:
    """Aggregated context snapshot for a Copilot analysis.

    This is the single source of truth for any decision the Copilot makes.
    All state is gathered here before analysis begins.
    """

    def __init__(
        self,
        app_id: str,
        authority_level: AuthorityLevel = AuthorityLevel.OBSERVER,
        config: CopilotConfig | None = None,
    ) -> None:
        self.app_id = app_id
        self.authority_level = authority_level
        self.config = config or CopilotConfig()
        self.timestamp = datetime.now(UTC)

        # Core components (populated by builders)
        self.finding: dict[str, Any] | None = None
        self.evidence: list[dict[str, Any]] = []
        self.verdict: dict[str, Any] | None = None
        self.confidence_score: dict[str, Any] | None = None
        self.decision_history: list[dict[str, Any]] = []
        self.memory: list[dict[str, Any]] = []
        self.system_state: dict[str, Any] = {}
        self.policies: list[dict[str, Any]] = []

    def set_finding(self, finding: dict[str, Any]) -> None:
        self.finding = finding
        logger.debug("Context: finding set: %s", finding.get("id", "unknown"))

    def add_evidence(self, evidence: dict[str, Any]) -> None:
        self.evidence.append(evidence)

    def set_verdict(self, verdict: dict[str, Any]) -> None:
        self.verdict = verdict

    def set_confidence_score(self, score: dict[str, Any]) -> None:
        self.confidence_score = score

    def set_decision_history(self, history: list[dict[str, Any]]) -> None:
        self.decision_history = history

    def set_memory(self, memory: list[dict[str, Any]]) -> None:
        self.memory = memory

    def set_system_state(self, state: dict[str, Any]) -> None:
        self.system_state = state

    def set_policies(self, policies: list[dict[str, Any]]) -> None:
        self.policies = policies

    def decision_band(self) -> str:
        conf = self._effective_confidence()
        return DecisionConfidence.band(conf)

    def needs_approval(self) -> bool:
        conf = self._effective_confidence()
        return DecisionConfidence.needs_approval(conf, self.authority_level)

    def _effective_confidence(self) -> float:
        if self.confidence_score:
            return self.confidence_score.get("score", 0.0)
        if self.verdict:
            return self.verdict.get("confidence", 0.0)
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "authority_level": self.authority_level.value,
            "timestamp": self.timestamp.isoformat(),
            "finding": self.finding,
            "evidence": self.evidence,
            "verdict": self.verdict,
            "confidence_score": self.confidence_score,
            "decision_history": self.decision_history[-10:],
            "memory": self.memory[-5:],
            "system_state": self.system_state,
            "policies": self.policies,
            "decision_band": self.decision_band(),
            "needs_approval": self.needs_approval(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2)
