from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("orion.core.reports.acceptance.scraper")

HACKERONE_HACKTIVITY = "https://hackerone.com/hacktivity"
HACKERONE_REPORT = "https://hackerone.com/reports/{}"
HACKERONE_GRAPHQL = "https://hackerone.com/graphql"

# GraphQL query for disclosed reports (mimics the hacktivity page)
_HACKTIVITY_QUERY = """
query SearchQuery($query: String, $size: Int, $from: Int) {
  search(query: $query, size: $size, from: $from) {
    nodes {
      ... on Report {
        id
        dbid
        title
        severity
        disclosed_at
        bounty_amount
        currency
        vulnerability_type
        reporter {
          username
        }
        team {
          handle
          name
        }
      }
    }
  }
}
"""

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "none",
    "informative": "informative",
}


def _extract_report_id(url: str) -> int | None:
    m = re.search(r"/reports/(\d+)", url)
    return int(m.group(1)) if m else None


def _parse_disclosed_report(report_id: int, html: str) -> dict[str, Any] | None:
    """Parse a disclosed HackerOne report page for structured data."""
    soup = BeautifulSoup(html, "html.parser")

    data: dict[str, Any] = {
        "report_id": report_id,
        "platform": "hackerone",
        "vulnerability_type": "unknown",
        "severity": "medium",
        "bounty_amount": None,
        "currency": "USD",
        "program": "",
        "has_poc": False,
        "has_evidence": False,
        "description_length": 0,
    }

    ld_json = soup.find("script", type="application/ld+json")
    if ld_json and ld_json.string:
        try:
            parsed = json.loads(ld_json.string)
            if isinstance(parsed, dict):
                data["description_length"] = len(parsed.get("description", "") or "")
        except (json.JSONDecodeError, TypeError):
            pass

    next_data = soup.find("script", id="__NEXT_DATA__")
    if next_data and next_data.string:
        try:
            payload = json.loads(next_data.string)
            props = payload.get("props", {}).get("pageProps", {})
            report = props.get("report") or props.get("initialReport") or {}
            if report:
                data["vulnerability_type"] = report.get("vulnerability_information", {}).get(
                    "vulnerability_type", "unknown"
                )
                data["severity"] = SEVERITY_MAP.get((report.get("severity") or "").lower(), "medium")
                data["bounty_amount"] = report.get("bounty_amount")
                data["currency"] = report.get("currency", "USD")
                data["program"] = report.get("team", {}).get("name") or report.get("team", {}).get("handle") or ""
                data["has_poc"] = bool(report.get("vulnerability_information", {}).get("poc"))
                data["has_evidence"] = bool(report.get("vulnerability_information", {}).get("evidence"))
                return data
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass

    title_tag = soup.find("title")
    if title_tag and title_tag.string:
        text = title_tag.string.lower()
        for vt in ["xss", "sqli", "ssrf", "idor", "rce", "csrf", "open redirect"]:
            if vt in text:
                data["vulnerability_type"] = vt
                break

    sev_el = soup.select_one("[class*='severity'], [data-severity]")
    if sev_el:
        sev_text = (sev_el.get("data-severity") or sev_el.get_text() or "").lower().strip()
        data["severity"] = SEVERITY_MAP.get(sev_text, data["severity"])

    return data if data["vulnerability_type"] != "unknown" or data["bounty_amount"] else None


def scrape_hacktivity_pages(
    max_pages: int = 3,
    per_page: int = 25,
    timeout: float = 30.0,
    delay: float = 1.0,
) -> list[dict[str, Any]]:
    """Scrape public disclosed reports from HackerOne hacktivity.

    Fetches the hacktivity feed and extracts report IDs, then fetches
    individual disclosed report pages for structured data extraction
    (vulnerability type, severity, bounty amount, program info).

    Returns a list of structured records ready to feed into
    AcceptanceLearner.record_manual_outcome().
    """
    results: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    page = 0

    try:
        client = httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=True)

        for page in range(1, max_pages + 1):
            try:
                url = (
                    f"{HACKERONE_HACKTIVITY}"
                    f"?sort_field=latest_disclosable_activity_at"
                    f"&query=disclosed%3Atrue"
                    f"&page={page}"
                )
                resp = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                resp.raise_for_status()
            except Exception as exc:
                logger.warning("Failed to fetch hacktivity page %d: %s", page, exc)
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            report_links = set()

            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                rid = _extract_report_id(href)
                if rid and rid not in seen_ids:
                    report_links.add(rid)

            if not report_links:
                logger.info("No report links found on page %d (may need JS rendering)", page)
                js_data = _try_extract_json_embed(resp.text, per_page, page)
                for rid in js_data:
                    if rid not in seen_ids:
                        report_links.add(rid)

            if not report_links:
                logger.info("No more reports found on page %d, stopping", page)
                break

            for rid in sorted(report_links):
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)

                try:
                    time.sleep(delay)
                    report_resp = client.get(
                        HACKERONE_REPORT.format(rid),
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                    report_resp.raise_for_status()
                except Exception as exc:
                    logger.debug("Failed to fetch report %d: %s", rid, exc)
                    continue

                parsed = _parse_disclosed_report(rid, report_resp.text)
                if parsed:
                    results.append(parsed)

            if len(report_links) < per_page:
                break

        client.close()
    except Exception as exc:
        logger.exception("Hacktivity scraper failed: %s", exc)

    logger.info(
        "Scraped %d disclosed reports from %d hacktivity pages",
        len(results),
        page,
    )
    return results


def _try_extract_json_embed(html: str, per_page: int, page: int) -> set[int]:
    """Extract report IDs from JSON embedded in the hacktivity page."""
    ids: set[int] = set()

    next_data_match = re.search(
        r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        html,
        re.DOTALL,
    )
    if next_data_match:
        try:
            payload = json.loads(next_data_match.group(1))
            reports = payload.get("props", {}).get("pageProps", {}).get("reports", [])
            for r in reports:
                rid = r.get("dbid") or r.get("id")
                if rid:
                    ids.add(int(rid))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    if not ids:
        ids.update(int(m) for m in re.findall(r"/reports/(\d{5,})", html))

    return ids


def hacktivity_to_observations(
    scraped: list[dict[str, Any]],
    learner: Any = None,
) -> list[dict[str, Any]]:
    """Convert scraped hacktivity records into AcceptanceLearner observations.

    Each record is classified as 'accepted' (has bounty_amount)
    or 'rejected' (no bounty, disclosed without payout).
    Quality dimensions are estimated from report characteristics.
    """
    observations: list[dict[str, Any]] = []

    for record in scraped:
        has_bounty = record.get("bounty_amount") is not None and record["bounty_amount"] > 0
        dimensions = {
            "evidence": 1.0 if record.get("has_evidence") else 0.3,
            "reproducibility": 0.8,
            "clarity": 0.6,
            "impact_severity": {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}.get(
                record.get("severity", "medium"), 0.5
            ),
            "completeness": 0.7 if record.get("has_poc") else 0.4,
            "confidence": 0.9 if has_bounty else 0.5,
        }

        # Estimate quality score from dimensions
        score = sum(dimensions.values()) / len(dimensions)

        evidence_count = sum(
            [
                1 if record.get("has_evidence") else 0,
                1 if record.get("has_poc") else 0,
            ]
        )

        observations.append(
            {
                "platform": record.get("platform", "hackerone"),
                "program": record.get("program", "unknown"),
                "vulnerability_type": record.get("vulnerability_type", "unknown"),
                "outcome": "accepted" if has_bounty else "rejected",
                "dimensions": dimensions,
                "score": round(score, 4),
                "severity": record.get("severity", "medium"),
                "evidence_count": evidence_count,
                "source": "hacktivity_scraper",
            }
        )

    return observations


def feed_hacktivity_to_learner(
    max_pages: int = 3,
    delay: float = 1.0,
) -> int:
    """Scrape hacktivity and feed results into the AcceptanceLearner."""
    from reportsmith.reports.acceptance.learner import AcceptanceLearner

    scraped = scrape_hacktivity_pages(
        max_pages=max_pages,
        per_page=25,
        timeout=30.0,
        delay=delay,
    )

    if not scraped:
        logger.info("No hacktivity records scraped")
        return 0

    observations = hacktivity_to_observations(scraped)
    learner = AcceptanceLearner(load_persisted=True)

    count = 0
    for obs in observations:
        try:
            learner.record_manual_outcome(
                platform=obs["platform"],
                program=obs["program"],
                vulnerability_type=obs["vulnerability_type"],
                outcome=obs["outcome"],
                dimensions=obs["dimensions"],
                score=obs["score"],
                severity=obs["severity"],
                evidence_count=obs["evidence_count"],
            )
            count += 1
        except Exception as exc:
            logger.debug("Failed to record observation: %s", exc)

    logger.info("Fed %d hacktivity observations into AcceptanceLearner", count)
    return count
