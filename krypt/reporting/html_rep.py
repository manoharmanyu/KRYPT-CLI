"""
Standalone HTML Report Generator for KRYPT CLI.
Creates self-contained, responsive cybersecurity assessment reports with dark-mode styling.
"""

from datetime import datetime
import html
from typing import Any, Dict, List, Optional
from jinja2 import Template

from krypt.database.models import FindingModel

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KRYPT CLI Security Assessment Report - {{ target }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --text-primary: #c9d1d9;
            --text-heading: #58a6ff;
            --border-color: #30363d;
            --crit: #f85149;
            --high: #ff7b72;
            --med: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            line-height: 1.6;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #1f242c 0%, #161b22 100%);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        }
        .header h1 {
            color: var(--text-heading);
            margin: 0 0 0.5rem 0;
            font-size: 2rem;
            letter-spacing: 1px;
        }
        .tagline {
            color: #8b949e;
            font-size: 0.95rem;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 1rem;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        .meta-item {
            background: var(--bg-card);
            padding: 0.75rem 1rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }
        .meta-label {
            font-size: 0.8rem;
            color: #8b949e;
            text-transform: uppercase;
        }
        .meta-val {
            font-size: 1.1rem;
            font-weight: 600;
            color: #f0f6fc;
        }
        .scorecard {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        .score-box {
            flex: 1;
            min-width: 140px;
            padding: 1.25rem;
            border-radius: 8px;
            text-align: center;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
        }
        .score-box.critical { border-top: 4px solid var(--crit); }
        .score-box.high { border-top: 4px solid var(--high); }
        .score-box.medium { border-top: 4px solid var(--med); }
        .score-box.low { border-top: 4px solid var(--low); }
        .score-num { font-size: 2rem; font-weight: bold; }
        .score-lbl { font-size: 0.85rem; color: #8b949e; text-transform: uppercase; }

        .finding-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
        }
        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            font-size: 0.75rem;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background-color: var(--crit); color: #fff; }
        .badge-HIGH { background-color: var(--high); color: #fff; }
        .badge-MEDIUM { background-color: var(--med); color: #000; }
        .badge-LOW { background-color: var(--low); color: #fff; }
        .badge-INFO { background-color: var(--info); color: #fff; }
        
        .finding-body {
            padding: 1.5rem;
        }
        .detail-row {
            margin-bottom: 1rem;
        }
        .detail-label {
            font-weight: 600;
            color: #58a6ff;
            margin-bottom: 0.25rem;
            font-size: 0.9rem;
            text-transform: uppercase;
        }
        pre {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            color: #e6edf3;
            font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
            word-break: break-word;
        }
        .footer {
            text-align: center;
            padding: 2rem 0;
            color: #8b949e;
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 3rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>KRYPT CLI Assessment Report</h1>
            <div class="tagline">OSINT • RECON • DISCOVER • ASSESS</div>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Target</div>
                    <div class="meta-val">{{ target }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Timestamp</div>
                    <div class="meta-val">{{ timestamp }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Findings</div>
                    <div class="meta-val">{{ findings|length }}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Author</div>
                    <div class="meta-val">Gaddam Manyu</div>
                </div>
            </div>
        </div>

        <div class="scorecard">
            <div class="score-box critical">
                <div class="score-num" style="color: var(--crit)">{{ counts.critical }}</div>
                <div class="score-lbl">Critical</div>
            </div>
            <div class="score-box high">
                <div class="score-num" style="color: var(--high)">{{ counts.high }}</div>
                <div class="score-lbl">High</div>
            </div>
            <div class="score-box medium">
                <div class="score-num" style="color: var(--med)">{{ counts.medium }}</div>
                <div class="score-lbl">Medium</div>
            </div>
            <div class="score-box low">
                <div class="score-num" style="color: var(--low)">{{ counts.low }}</div>
                <div class="score-lbl">Low</div>
            </div>
        </div>

        <h2>Assessment Findings</h2>
        {% if not findings %}
        <div class="finding-card" style="padding: 2rem; text-align: center; color: #3fb950;">
            ✓ No security vulnerabilities identified within authorized testing scope.
        </div>
        {% endif %}

        {% for f in findings %}
        <div class="finding-card">
            <div class="finding-header">
                <div style="font-weight: bold; font-size: 1.1rem; color: #f0f6fc;">
                    {{ f.id }} &mdash; {{ f.vulnerability }}
                </div>
                <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
            </div>
            <div class="finding-body">
                <div class="detail-row">
                    <div class="detail-label">Location</div>
                    <div><strong>Endpoint:</strong> {{ f.endpoint }} &nbsp;|&nbsp; <strong>Parameter:</strong> {{ f.parameter or 'N/A' }} &nbsp;|&nbsp; <strong>Module:</strong> {{ f.module }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Evidence & Observations</div>
                    <pre>{{ f.evidence }}</pre>
                </div>
                {% if f.impact %}
                <div class="detail-row">
                    <div class="detail-label">Impact</div>
                    <div>{{ f.impact }}</div>
                </div>
                {% endif %}
                {% if f.remediation %}
                <div class="detail-row">
                    <div class="detail-label">Remediation</div>
                    <div>{{ f.remediation }}</div>
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}

        <div class="footer">
            Generated by <strong>KRYPT CLI v0.1.0</strong> &bull; Created by Gaddam Manyu (@manoharmanyu)<br>
            Strict scope enforcement active. Authorized security assessment only.
        </div>
    </div>
</body>
</html>
"""


def generate_html_report(
    target_url: str,
    findings: List[FindingModel],
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Render standalone HTML report using Jinja2."""
    template = Template(HTML_TEMPLATE)
    counts = {
        "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high": sum(1 for f in findings if f.severity == "HIGH"),
        "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
        "low": sum(1 for f in findings if f.severity == "LOW"),
    }
    return template.render(
        target=target_url,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        findings=findings,
        counts=counts,
        metadata=metadata or {}
    )
