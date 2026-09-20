"""ReportSmith report pipeline: templates, critic, optimizer, factory."""

from __future__ import annotations

from .critic import ReportCritic
from .factory import ReportPackage
from .optimizer import ReportOptimizer
from .templates import render_report

__all__ = ["ReportCritic", "ReportPackage", "ReportOptimizer", "render_report"]
