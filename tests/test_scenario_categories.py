"""Tests for the scenario_categories.py taxonomy used by `generate-category`.

Pure data-integrity checks — nothing here talks to an LLM.
"""

from __future__ import annotations

import pytest

from forge_incident.scenario_categories import (
    CATEGORIES,
    DOMAINS,
    all_category_ids,
    categories_in_domain,
    domain_ids,
    get_category,
    get_domain,
)


def test_every_category_has_a_unique_id():
    ids = all_category_ids()
    assert len(ids) == len(set(ids))
    assert len(ids) >= 40, "taxonomy should be comprehensive, not a trimmed-down MVP list"


def test_every_domain_has_at_least_one_category():
    for domain in DOMAINS:
        cats = categories_in_domain(domain.id)
        assert cats, f"domain {domain.id!r} has zero categories"


def test_every_category_references_a_known_domain():
    known = set(domain_ids())
    for category in CATEGORIES:
        assert category.domain in known, (
            f"{category.id} references unknown domain {category.domain!r}"
        )


def test_every_category_has_required_text_fields():
    for category in CATEGORIES:
        assert category.name.strip()
        assert category.summary.strip()
        assert category.source.strip()
        assert len(category.summary) > 40, (
            f"{category.id} summary looks too thin to prompt an LLM well"
        )


def test_get_category_round_trips():
    for category in CATEGORIES:
        assert get_category(category.id) is category


def test_get_category_raises_key_error_with_helpful_message():
    with pytest.raises(KeyError, match="Unknown scenario category"):
        get_category("does-not-exist")


def test_get_domain_raises_key_error_for_unknown_domain():
    with pytest.raises(KeyError):
        get_domain("does-not-exist")


def test_categories_in_domain_validates_domain_id():
    with pytest.raises(KeyError):
        categories_in_domain("does-not-exist")


def test_gcp_and_cross_cutting_domains_cover_the_bundled_scenarios():
    """The taxonomy should include a category matching each bundled hand-written
    scenario's premise (phishing_to_exfil, gcp_key_compromise), so instructors
    can generate fresh variants of the same idea via generate-category."""
    ids = set(all_category_ids())
    assert "gcp-leaked-service-account-key" in ids
    assert "cross-phishing-lateral-exfil" in ids


def test_aws_and_azure_categories_declare_their_native_log_sources():
    for category in categories_in_domain("aws"):
        assert "aws_cloudtrail" in category.primary_log_sources
    for category in categories_in_domain("azure"):
        assert "azure_activity" in category.primary_log_sources
