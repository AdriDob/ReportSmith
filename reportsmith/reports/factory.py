"""Report Factory — finding + evidence -> submission-ready package ($0).

Reuses reportsmith.reports.templates.render_report (SSOT, no duplicate).
Adds a sellable service layer: ReportPackage (markdown + checklist + pricing)
for hunters who find bugs but can't write professional reports ($50-150/gig).
Human Gate: preparing != submitting. Submit stays manual/approved.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("ownex.reports.factory")

_VALID_PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "immunefi", "h1", "bc", "inti")

_GIG_PRICES = {"basic": 50.0, "standard": 90.0, "premium": 150.0}


@dataclass(slots=True)
class ReportPackage:
    id: str
    platform: str
    title: str
    markdown: str = ""
    checklist: list[str] = field(default_factory=list)
    tier: str = "standard"
    price_usd: float = 90.0
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _checklist_for(platform: str) -> list[str]:
    base = [
        "Título claro con tipo de vuln + asset",
        "Pasos de reproducción numerados y ejecutables",
        "PoC (curl/python) fiel a la request real, auth redactado",
        "Impacto de negocio explícito (no solo técnico)",
        "CVSS + CWE incluidos",
        "Remediación accionable",
    ]
    if platform in ("intigriti", "inti"):
        base.append("Evidence checklist Intigriti completo")
    if platform == "immunefi":
        base.append("Clasificación de severidad Immunefi + asset on-chain si aplica")
    return base


def build_package(
    platform: str,
    data: dict[str, Any],
    tier: str = "standard",
) -> ReportPackage | None:
    """Build a submission-ready package. None = invalid input (honest, never fake)."""
    plat = (platform or "").strip().lower()
    if plat not in _VALID_PLATFORMS:
        return None
    if not isinstance(data, dict) or not str(data.get("title", "") or "").strip():
        return None
    try:
        from reportsmith.reports.templates import render_report
    except Exception:
        return None
    try:
        markdown = render_report(plat, dict(data))
    except Exception as exc:
        logger.warning("Report factory render failed: %s", type(exc).__name__)
        return None
    use_tier = tier if tier in _GIG_PRICES else "standard"
    title = str(data.get("title", "")).strip()[:120]
    pkg = ReportPackage(
        id=f"rpt_{plat}_{int(datetime.now(UTC).timestamp())}",
        platform=plat,
        title=title,
        markdown=markdown,
        checklist=_checklist_for(plat),
        tier=use_tier,
        price_usd=_GIG_PRICES[use_tier],
    )
    logger.info("Report package built: %s (%s/%s)", pkg.title, plat, use_tier)
    return pkg


def gig_catalog() -> list[dict[str, object]]:
    return [
        {"tier": "basic", "price_usd": 50.0, "includes": "Reporte markdown 1 plataforma + checklist"},
        {"tier": "standard", "price_usd": 90.0, "includes": "Reporte + PoC curl/python + CVSS/CWE + 1 revisión"},
        {"tier": "premium", "price_usd": 150.0, "includes": "Todo standard + 2 plataformas + remediation call notes"},
    ]
