"""
Tests for SEO Audit Engine (krypt seo).
"""

import pytest
from bs4 import BeautifulSoup
from krypt.recon.seo import SEOAnalyzer, SEOAuditReport


@pytest.mark.asyncio
async def test_seo_hardened_page_grade_a():
    """Verify that an optimized page achieves Grade A+ on the SEO analyzer."""
    # When analyzing the hardened app
    report = await SEOAnalyzer.analyze("http://127.0.0.1:8888?mode=hardened")
    
    assert report is not None
    assert report.score_percentage >= 90
    assert report.grade == "A+"
    assert report.title is not None
    assert "KRYPT" in report.title
    assert report.meta_description is not None
    assert report.canonical_url is not None
    assert report.sitemap_found is True
    assert report.has_structured_data is True
    assert len(report.items) >= 10

    # Ensure no critical failures
    failures = [item for item in report.items if item.status == "FAIL"]
    assert len(failures) == 0


@pytest.mark.asyncio
async def test_seo_unoptimized_page_low_grade():
    """Verify that an unoptimized/bare page receives appropriate warnings/failures."""
    # The default vulnerable lab has no meta description, viewport, og tags, etc.
    report = await SEOAnalyzer.analyze("http://127.0.0.1:8888?mode=vulnerable")
    
    assert report is not None
    assert report.score_percentage < 60
    assert report.grade in ("C", "F")
    
    # Check that missing items are flagged
    missing_items = [item.item for item in report.items if item.status in ("FAIL", "WARN")]
    assert "Meta Description" in missing_items
    assert "Viewport Tag" in missing_items
