"""
Search Engine Optimization (SEO) Audit Engine for KRYPT CLI.
Analyzes semantic structure, metadata, OpenGraph, Twitter cards, structured data, robots.txt, and sitemaps.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx

from krypt.core.http import http_client


@dataclass
class SEOCheckItem:
    category: str  # Metadata, Social, Semantic, Crawlability, Performance
    item: str
    status: str    # PASS, WARN, FAIL
    value: Optional[str]
    details: str
    recommendation: str


@dataclass
class SEOAuditReport:
    target_url: str
    score_percentage: int
    grade: str
    items: List[SEOCheckItem] = field(default_factory=list)
    title: Optional[str] = None
    meta_description: Optional[str] = None
    canonical_url: Optional[str] = None
    robots_rules: List[str] = field(default_factory=list)
    sitemap_found: bool = False
    has_structured_data: bool = False


class SEOAnalyzer:
    """Performs deep SEO audit on web applications."""

    @classmethod
    async def analyze(cls, target_url: str) -> SEOAuditReport:
        report = SEOAuditReport(target_url=target_url, score_percentage=0, grade="F")
        items: List[SEOCheckItem] = []

        resp = await http_client.get(target_url, follow_redirects=True)
        if not resp or resp.status_code != 200:
            items.append(SEOCheckItem(
                category="Crawlability",
                item="HTTP Availability",
                status="FAIL",
                value=str(resp.status_code) if resp else "Connection Error",
                details="Target URL failed to return HTTP 200 OK.",
                recommendation="Ensure the web server is online and returning HTTP 200 for search crawlers."
            ))
            report.items = items
            return report

        html_text = resp.text
        soup = BeautifulSoup(html_text, "html.parser")

        passed_weight = 0
        total_weight = 0

        def add_check(cat: str, name: str, passed: bool, val: Optional[str], details: str, rec: str, weight: int = 10, is_warn: bool = False):
            nonlocal passed_weight, total_weight
            total_weight += weight
            if passed:
                passed_weight += weight
                status = "PASS"
            elif is_warn:
                passed_weight += (weight // 2)
                status = "WARN"
            else:
                status = "FAIL"

            items.append(SEOCheckItem(
                category=cat,
                item=name,
                status=status,
                value=val,
                details=details,
                recommendation=rec if not passed else ""
            ))

        # 1. Title Tag
        title_tag = soup.find("title")
        title_text = title_tag.string.strip() if (title_tag and title_tag.string) else ""
        report.title = title_text
        if title_text:
            t_len = len(title_text)
            if 30 <= t_len <= 65:
                add_check("Metadata", "Title Tag", True, f"'{title_text}' ({t_len} chars)", "Title length is optimal (30-65 chars).", "", 10)
            elif t_len < 30:
                add_check("Metadata", "Title Tag", False, f"'{title_text}' ({t_len} chars)", "Title is present but too short.", "Lengthen title to 30-65 characters including primary target keywords.", 10, is_warn=True)
            else:
                add_check("Metadata", "Title Tag", False, f"'{title_text[:40]}...' ({t_len} chars)", "Title exceeds recommended limit of 65 characters.", "Shorten title to under 65 characters to avoid SERP truncation.", 10, is_warn=True)
        else:
            add_check("Metadata", "Title Tag", False, None, "Missing <title> tag.", "Add a concise, descriptive <title> tag.", 10)

        # 2. Meta Description
        desc_meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
        desc_text = desc_meta.get("content", "").strip() if desc_meta else ""
        report.meta_description = desc_text
        if desc_text:
            d_len = len(desc_text)
            if 70 <= d_len <= 160:
                add_check("Metadata", "Meta Description", True, f"{d_len} chars", "Meta description length is optimal (70-160 chars).", "", 10)
            else:
                add_check("Metadata", "Meta Description", False, f"{d_len} chars", "Meta description present but length is sub-optimal.", "Aim for 70 to 160 characters for search snippet previews.", 10, is_warn=True)
        else:
            add_check("Metadata", "Meta Description", False, None, "Missing <meta name='description'> tag.", "Add an informative meta description tag for search snippets.", 10)

        # 3. Viewport Meta (Mobile Optimization)
        viewport_meta = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
        if viewport_meta and "width=device-width" in viewport_meta.get("content", ""):
            add_check("Mobile", "Viewport Tag", True, viewport_meta.get("content"), "Mobile viewport properly configured.", "", 8)
        else:
            add_check("Mobile", "Viewport Tag", False, None, "Missing or incomplete viewport meta tag.", "Add <meta name='viewport' content='width=device-width, initial-scale=1.0'>.", 8)

        # 4. Canonical URL Tag
        canonical_tag = soup.find("link", attrs={"rel": re.compile(r"^canonical$", re.I)})
        canon_val = canonical_tag.get("href", "").strip() if canonical_tag else ""
        report.canonical_url = canon_val
        if canon_val:
            add_check("Metadata", "Canonical URL", True, canon_val, "Canonical URL tag present to prevent duplicate content.", "", 8)
        else:
            add_check("Metadata", "Canonical URL", False, None, "Missing <link rel='canonical'> tag.", "Add a canonical link pointing to the authoritative URL.", 8)

        # 5. Robots Meta Tag
        robots_meta = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
        robots_content = robots_meta.get("content", "").lower() if robots_meta else "default (index, follow)"
        if "noindex" in robots_content:
            add_check("Crawlability", "Robots Meta Directive", False, robots_content, "Robots tag is blocking search indexing ('noindex').", "Remove 'noindex' if this page is intended for public search indexing.", 10, is_warn=True)
        else:
            add_check("Crawlability", "Robots Meta Directive", True, robots_content, "Search indexing permitted.", "", 6)

        # 6. OpenGraph Social Metadata
        og_title = soup.find("meta", attrs={"property": "og:title"})
        og_desc = soup.find("meta", attrs={"property": "og:description"})
        og_type = soup.find("meta", attrs={"property": "og:type"})
        has_og = bool(og_title and og_desc and og_type)
        if has_og:
            add_check("Social Graph", "OpenGraph Tags", True, "og:title, og:description, og:type present", "Social sharing metadata configured.", "", 8)
        else:
            add_check("Social Graph", "OpenGraph Tags", False, None, "Missing OpenGraph social sharing meta tags.", "Add og:title, og:description, og:image, and og:type tags for social networks.", 8, is_warn=True)

        # 7. Twitter Card Metadata
        twitter_card = soup.find("meta", attrs={"name": "twitter:card"})
        if twitter_card:
            add_check("Social Graph", "Twitter Card", True, twitter_card.get("content"), "Twitter card metadata configured.", "", 6)
        else:
            add_check("Social Graph", "Twitter Card", False, None, "Missing twitter:card metadata.", "Add <meta name='twitter:card' content='summary_large_image'>.", 6, is_warn=True)

        # 8. Semantic Heading Hierarchy (H1, H2)
        h1_tags = soup.find_all("h1")
        h2_tags = soup.find_all("h2")
        if len(h1_tags) == 1:
            add_check("Semantic HTML", "Primary Heading (H1)", True, f"'{h1_tags[0].get_text(strip=True)[:40]}'", "Single, unambiguous H1 primary heading present.", "", 8)
        elif len(h1_tags) > 1:
            add_check("Semantic HTML", "Primary Heading (H1)", False, f"{len(h1_tags)} H1 tags found", "Multiple H1 headings detected.", "Use exactly one <h1> heading per page for clear document hierarchy.", 8, is_warn=True)
        else:
            add_check("Semantic HTML", "Primary Heading (H1)", False, "None", "Missing <h1> tag.", "Add a descriptive <h1> heading summarizing the page topic.", 8)

        if h2_tags:
            add_check("Semantic HTML", "Subheadings (H2)", True, f"{len(h2_tags)} subheadings", "Semantic document sub-structure established.", "", 6)
        else:
            add_check("Semantic HTML", "Subheadings (H2)", False, "None", "No <h2> headings detected.", "Structure content into sections with <h2> tags.", 6, is_warn=True)

        # 9. Structured Data (JSON-LD Schema.org)
        json_ld_tags = soup.find_all("script", attrs={"type": "application/ld+json"})
        if json_ld_tags:
            report.has_structured_data = True
            add_check("Structured Data", "Schema.org (JSON-LD)", True, f"{len(json_ld_tags)} schema block(s)", "Rich structured data detected for enhanced SERP presentation.", "", 8)
        else:
            add_check("Structured Data", "Schema.org (JSON-LD)", False, None, "Missing JSON-LD structured data.", "Implement Schema.org JSON-LD to qualify for rich snippets.", 8, is_warn=True)

        # 10. Image Alt Attributes
        images = soup.find_all("img")
        if images:
            missing_alt = sum(1 for img in images if not img.get("alt"))
            if missing_alt == 0:
                add_check("Accessibility & SEO", "Image Alt Text", True, f"{len(images)} images all with alt text", "All images have descriptive alt attributes.", "", 6)
            else:
                add_check("Accessibility & SEO", "Image Alt Text", False, f"{missing_alt}/{len(images)} images missing alt text", f"{missing_alt} image(s) lack alt attributes.", "Provide descriptive alt attributes for all content images.", 6, is_warn=True)

        # 11. Robots.txt check
        robots_url = urljoin(target_url, "/robots.txt")
        robots_resp = await http_client.get(robots_url)
        if robots_resp and robots_resp.status_code == 200 and "user-agent" in robots_resp.text.lower():
            report.robots_rules = [line.strip() for line in robots_resp.text.splitlines() if line.strip() and not line.startswith("#")]
            add_check("Crawlability", "robots.txt", True, f"{len(report.robots_rules)} rules", "Valid robots.txt file active on root domain.", "", 8)
        else:
            add_check("Crawlability", "robots.txt", False, None, "Missing or invalid /robots.txt file.", "Deploy a robots.txt file indicating indexing rules and sitemap location.", 8)

        # 12. Sitemap.xml check
        sitemap_url = urljoin(target_url, "/sitemap.xml")
        sitemap_resp = await http_client.get(sitemap_url)
        if sitemap_resp and sitemap_resp.status_code == 200 and ("<urlset" in sitemap_resp.text or "<sitemapindex" in sitemap_resp.text):
            report.sitemap_found = True
            add_check("Crawlability", "XML Sitemap", True, "/sitemap.xml", "Valid XML sitemap detected.", "", 8)
        else:
            add_check("Crawlability", "XML Sitemap", False, None, "Missing or invalid /sitemap.xml file.", "Publish an XML sitemap to help search engines discover all pages.", 8)

        score_pct = int((passed_weight / total_weight) * 100) if total_weight > 0 else 0
        report.score_percentage = score_pct

        if score_pct >= 90:
            report.grade = "A+"
        elif score_pct >= 80:
            report.grade = "A"
        elif score_pct >= 65:
            report.grade = "B"
        elif score_pct >= 50:
            report.grade = "C"
        else:
            report.grade = "F"

        report.items = items
        return report
