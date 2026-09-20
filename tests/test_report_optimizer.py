from __future__ import annotations

from unittest.mock import MagicMock, patch

from reportsmith.reports.optimizer import (
    CWE_MAP,
    PLATFORM_REMEDIATION_PREFIX,
    REMEDIATION_DB,
    VULN_ALIASES,
    ReportContext,
    ReportContextBuilder,
    ReportOptimizer,
    _generate_impact_text,
    _parse_notes,
    get_remediation,
)

# ── Remediation helpers ──────────────────────────────────────


def test_get_remediation_known_vuln():
    result = get_remediation("idor")
    assert "server-side access control" in result["summary"]
    assert "owasp" in result["owasp_reference"].lower()
    assert len(result["rendered"]) > 50


def test_get_remediation_with_alias():
    r1 = get_remediation("idor")
    r2 = get_remediation("insecure_direct_object_reference")
    assert r1["summary"] == r2["summary"]


def test_get_remediation_unknown_vuln():
    result = get_remediation("nonexistent_vuln_type")
    assert "security best practices" in result["summary"]


def test_get_remediation_platform_prefix():
    for platform in ("hackerone", "bugcrowd", "intigriti", "immunefi"):
        result = get_remediation("xss", platform=platform)
        assert platform in PLATFORM_REMEDIATION_PREFIX
        assert result["rendered"].startswith(PLATFORM_REMEDIATION_PREFIX[platform])


def test_remediation_db_completeness():
    for vuln_type in VULN_ALIASES:
        key = VULN_ALIASES[vuln_type]
        assert key in REMEDIATION_DB, f"Missing remediation for {vuln_type} → {key}"


def test_remediation_db_structure():
    for key, remediation in REMEDIATION_DB.items():
        assert remediation.summary, f"Empty summary for {key}"
        assert remediation.details, f"Empty details for {key}"
        assert remediation.owasp_reference, f"Empty reference for {key}"
        assert remediation.severity_multiplier > 0


def test_cwe_map_completeness():
    for vuln_type in VULN_ALIASES:
        key = VULN_ALIASES[vuln_type]
        assert key in CWE_MAP, f"Missing CWE for {vuln_type} → {key}"


def test_cwe_map_structure():
    for key, (cwe_id, cwe_name) in CWE_MAP.items():
        assert cwe_id.startswith("CWE-"), f"Invalid CWE format for {key}: {cwe_id}"
        assert cwe_name, f"Empty CWE name for {key}"


# ── Impact text generator ────────────────────────────────────


def test_generate_impact_known():
    text = _generate_impact_text("idor", "high")
    assert "private data" in text
    assert len(text) > 20


def test_generate_impact_unknown_vuln():
    text = _generate_impact_text("unknown", "high")
    assert "significant security risk" in text


def test_generate_impact_severity_variations():
    for sev in ("critical", "high", "medium", "low"):
        text = _generate_impact_text("ssrf", sev)
        assert text, f"Empty text for {sev}"
    assert "internal services" in _generate_impact_text("ssrf", "critical")


# ── Notes parser ─────────────────────────────────────────────


def test_parse_notes_empty():
    assert _parse_notes("") == {}
    assert _parse_notes("") == {}  # None handled by caller


def test_parse_notes_json():
    result = _parse_notes('{"reproduction_steps": "step 1", "impact": "high"}')
    assert result["reproduction_steps"] == "step 1"
    assert result["impact"] == "high"


def test_parse_notes_invalid_json():
    result = _parse_notes("just a string, not json")
    assert result == {}


# ── ReportContextBuilder ─────────────────────────────────────


@patch("reportsmith.reports.optimizer.get_db_session")
@patch("reportsmith.reports.optimizer.get_quality_scorer")
@patch("reportsmith.reports.optimizer.get_acceptance_learner")
def test_builder_returns_context_for_valid_finding(mock_get_learner, mock_get_scorer, mock_get_session):
    mock_session = MagicMock()
    mock_get_session.return_value = mock_session

    mock_finding = MagicMock()
    mock_finding.id = 1
    mock_finding.title = "Test IDOR"
    mock_finding.description = "An IDOR vulnerability was found"
    mock_finding.severity = "high"
    mock_finding.status = "confirmed"
    mock_finding.vulnerability_type = "idor"
    mock_finding.endpoint_id = 10
    mock_finding.target_id = 20
    mock_finding.notes = ""
    mock_session.query.return_value.filter.return_value.first.return_value = mock_finding
    mock_session.query.return_value.join.return_value.filter.return_value.count.return_value = 3

    mock_qs = MagicMock()
    mock_qs.score = 85.0
    mock_qs.dimensions = {
        "evidence": 0.9,
        "reproducibility": 0.85,
        "clarity": 0.8,
        "impact_severity": 0.9,
        "completeness": 0.8,
        "confidence": 0.85,
    }
    mock_scorer = MagicMock()
    mock_scorer.score.return_value = mock_qs
    mock_get_scorer.return_value = mock_scorer

    mock_pred = MagicMock()
    mock_pred.probability = 0.75
    mock_pred.recommendations = ["Add more evidence"]
    mock_pred.weak_dimensions = ["evidence"]
    mock_learner = MagicMock()
    mock_learner.predict.return_value = mock_pred
    mock_get_learner.return_value = mock_learner

    builder = ReportContextBuilder()
    ctx = builder.build(1)
    assert ctx is not None
    assert ctx.finding["title"] == "Test IDOR"
    assert ctx.quality_score == 85.0
    assert ctx.evidence_count == 3
    assert ctx.acceptance_probability == 0.75
    assert ctx.platform == "hackerone"


@patch("reportsmith.reports.optimizer.get_db_session")
def test_builder_returns_none_for_missing_finding(mock_get_session):
    mock_session = MagicMock()
    mock_session.query.return_value.filter.return_value.first.return_value = None
    mock_get_session.return_value = mock_session

    builder = ReportContextBuilder()
    ctx = builder.build(999)
    assert ctx is None


# ── ReportOptimizer ──────────────────────────────────────────


@patch("reportsmith.reports.optimizer.ReportContextBuilder")
@patch("reportsmith.reports.optimizer.get_bus")
def test_optimize_returns_full_result(mock_get_bus, mock_builder_cls):
    mock_ctx = ReportContext(
        finding={"title": "Test", "vulnerability_type": "idor", "severity": "high", "description": "desc"},
        quality_score=85.0,
        quality_dimensions={"evidence": 90.0},
        evidence_count=3,
        acceptance_probability=0.75,
        acceptance_recommendations=["Add more evidence"],
        acceptance_weak_dimensions=["evidence"],
        remediation={"summary": "Fix it", "rendered": "## Fix\nFix it", "details": "Do X", "owasp_reference": ""},
        platform="hackerone",
        template_vars={"rendered_report": "# Report\n...", "title": "Test", "quality_score": 85.0},
        critic_score=90.0,
        critic_verdict="ready",
        critic_suggestions=["Add CVSS"],
    )
    mock_builder = MagicMock()
    mock_builder.build.return_value = mock_ctx
    mock_builder_cls.return_value = mock_builder

    mock_bus = MagicMock()
    mock_get_bus.return_value = mock_bus

    optimizer = ReportOptimizer(builder=mock_builder)
    result = optimizer.optimize(1)
    assert result is not None
    assert result["finding_id"] == 1
    assert result["quality_score"] == 85.0
    assert result["acceptance_probability"] == 0.75
    assert result["critic_verdict"] == "ready"
    assert "rendered_report" in result
    mock_bus.publish.assert_called_once()


@patch("reportsmith.reports.optimizer.ReportContextBuilder")
@patch("reportsmith.reports.optimizer.get_bus")
def test_optimize_returns_none_for_missing(mock_get_bus, mock_builder_cls):
    mock_builder = MagicMock()
    mock_builder.build.return_value = None
    mock_builder_cls.return_value = mock_builder

    optimizer = ReportOptimizer(builder=mock_builder)
    result = optimizer.optimize(999)
    assert result is None


@patch("reportsmith.reports.optimizer.ReportContextBuilder")
@patch("reportsmith.reports.optimizer.get_bus")
def test_batch_optimize(mock_get_bus, mock_builder_cls):
    mock_ctx = ReportContext(
        finding={"title": "Test", "vulnerability_type": "xss", "severity": "medium", "description": "desc"},
        quality_score=70.0,
        quality_dimensions={},
        evidence_count=1,
        acceptance_probability=0.5,
        platform="hackerone",
        template_vars={"rendered_report": "# Report", "title": "Test", "quality_score": 70.0},
    )
    mock_builder = MagicMock()
    mock_builder.build.side_effect = [mock_ctx, None, mock_ctx]
    mock_builder_cls.return_value = mock_builder

    mock_bus = MagicMock()
    mock_get_bus.return_value = mock_bus

    optimizer = ReportOptimizer(builder=mock_builder)
    results = optimizer.batch_optimize([1, 2, 3])
    assert len(results) == 2  # skip the None
    assert results[0]["finding_id"] == 1
    assert results[1]["finding_id"] == 3


@patch("reportsmith.reports.optimizer.ReportContextBuilder")
@patch("reportsmith.reports.optimizer.get_bus")
def test_optimize_publishes_event(mock_get_bus, mock_builder_cls):
    mock_ctx = ReportContext(
        finding={"title": "T", "vulnerability_type": "sqli", "severity": "critical", "description": "d"},
        quality_score=95.0,
        acceptance_probability=0.8,
        critic_verdict="ready",
        platform="bugcrowd",
        template_vars={"rendered_report": "# R", "title": "T", "quality_score": 95.0},
    )
    mock_builder = MagicMock()
    mock_builder.build.return_value = mock_ctx
    mock_builder_cls.return_value = mock_builder

    mock_bus = MagicMock()
    mock_get_bus.return_value = mock_bus

    optimizer = ReportOptimizer(builder=mock_builder)
    optimizer.optimize(1, platform="bugcrowd")
    mock_bus.publish.assert_called_once_with(
        "report:optimized",
        finding_id=1,
        platform="bugcrowd",
        quality_score=95.0,
        acceptance_probability=0.8,
        critic_verdict="ready",
    )


# ── Edge cases ───────────────────────────────────────────────


def test_get_remediation_case_insensitive():
    assert get_remediation("IDOR")["summary"] == get_remediation("idor")["summary"]
    assert get_remediation("SQL_Injection")["summary"] == get_remediation("sqli")["summary"]


def test_get_remediation_strip_whitespace():
    assert get_remediation("  xss  ")["summary"] == get_remediation("xss")["summary"]


def test_all_vuln_aliases_resolve():
    for alias in VULN_ALIASES:
        key = VULN_ALIASES[alias]
        assert key in REMEDIATION_DB, f"Alias {alias} → {key} not in REMEDIATION_DB"
        assert key in CWE_MAP, f"Alias {alias} → {key} not in CWE_MAP"
