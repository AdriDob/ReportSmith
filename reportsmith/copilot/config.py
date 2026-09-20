"""Copilot configuration via environment/settings."""

from __future__ import annotations

import logging
import os

from reportsmith.copilot.permissions import AuthorityLevel

logger = logging.getLogger("orion.core.copilot.config")


class CopilotConfig:
    """Configuration for the Senior Copilot Agent.

    Reads from environment variables with sensible defaults.
    """

    def __init__(self) -> None:
        self.authority_level: AuthorityLevel = AuthorityLevel.from_str(
            os.environ.get("COPILOT_AUTHORITY", "observer"),
        )
        self.min_confidence_auto: float = float(
            os.environ.get("COPILOT_MIN_CONFIDENCE_AUTO", "0.70"),
        )
        self.max_decisions_logged: int = int(
            os.environ.get("COPILOT_MAX_DECISIONS", "1000"),
        )

    def to_dict(self) -> dict:
        return {
            "authority_level": self.authority_level.value,
            "min_confidence_auto": self.min_confidence_auto,
            "max_decisions_logged": self.max_decisions_logged,
        }
