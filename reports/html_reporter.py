"""Interactive Cybersecurity SaaS HTML Report Generator for PromptShield.

Produces a self-contained, presentation-ready HTML dashboard featuring:
- Executive cybersecurity KPIs (Grade, Risk Score, Defenses, Controls, Uncertain)
- Embedded Chart.js visualizations (Severity Donut, Category Defense, OWASP Top 10)
- Interactive tabbed & searchable vulnerability explorer
- Actionable remediation playbook cards
- Single-file design with inline SVG favicon and print/PDF export support
"""

import json
from pathlib import Path
from promptshield.attacks.models import Severity
from promptshield.detectors.base import DetectionStatus
from promptshield.scoring.models import ScanSummary


class HtmlReporter:
    """Generates self-contained HTML audit reports with interactive cybersecurity dashboard."""

    @staticmethod
    def generate(summary: ScanSummary, output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Grade color mapping
        grade_colors = {
            "A": "#10b981",  # Emerald
            "B": "#06b6d4",  # Cyan
            "C": "#f59e0b",  # Amber
            "D": "#f97316",  # Orange
            "F": "#ef4444",  # Red
        }
        grade_color = grade_colors.get(summary.letter_grade, "#64748b")
        grade_verdict = (
            "🧬 Exceptional Hardening — Zero Critical Leaks"
            if summary.letter_grade == "A"
            else "🛡️ Resilient Posture — Low Residual Risk"
            if summary.letter_grade == "B"
            else "⚠️ Moderate Risk — Guardrail Gaps Detected"
            if summary.letter_grade == "C"
            else "🚨 High Vulnerability Exposure"
            if summary.letter_grade == "D"
            else "💥 Critically Vulnerable — Multiple Exploits Succeeded"
        )

        # Filter categories and stats
        controls_total = sum(1 for r in summary.results if r.is_control)
        controls_passed = sum(1 for r in summary.results if r.is_control and r.status == DetectionStatus.PASS)

        # Severity breakdown of confirmed exploits
        crit_fails = sum(1 for r in summary.results if r.status == DetectionStatus.FAIL and r.severity == Severity.CRITICAL and not r.is_control)
        high_fails = sum(1 for r in summary.results if r.status == DetectionStatus.FAIL and r.severity == Severity.HIGH and not r.is_control)
        med_fails = sum(1 for r in summary.results if r.status == DetectionStatus.FAIL and r.severity == Severity.MEDIUM and not r.is_control)
        low_fails = sum(1 for r in summary.results if r.status == DetectionStatus.FAIL and r.severity == Severity.LOW and not r.is_control)

        # Categories for bar chart
        categories = list(summary.category_breakdown.keys())
        pass_rates = [summary.category_breakdown[c].pass_rate_pct for c in categories]

        # OWASP Top 10 breakdown
        owasp_labels = list(summary.owasp_breakdown.keys())
        owasp_rates = [summary.owasp_breakdown[k].pass_rate_pct for k in owasp_labels]

        # Prepare JSON string for client-side download
        raw_json_string = summary.model_dump_json(indent=2)
        escaped_json_string = (
            raw_json_string.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "")
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🧬 PromptShield Audit: {summary.target_name}</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🧬</text></svg>">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg-dark: #070d18;
      --card-bg: #0e1e38;
      --card-inner: #0a1628;
      --border: #1e3a5f;
      --border-accent: #0284c7;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #00f0ff;
      --primary-dim: rgba(0, 240, 255, 0.15);
      --success: #10b981;
      --success-dim: rgba(16, 185, 129, 0.15);
      --danger: #ef4444;
      --danger-dim: rgba(239, 68, 68, 0.15);
      --warning: #f59e0b;
      --warning-dim: rgba(245, 158, 11, 0.15);
      --purple: #a855f7;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }}
    body {{ background: var(--bg-dark); color: var(--text); padding: 2rem 1.5rem; line-height: 1.6; }}
    .container {{ max-width: 1320px; margin: 0 auto; }}

    /* Header & Navigation */
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }}
    .brand {{ display: flex; align-items: center; gap: 0.85rem; }}
    .brand-logo {{ font-size: 2.8rem; filter: drop-shadow(0 0 12px rgba(0, 240, 255, 0.6)); }}
    .brand-title h1 {{ font-size: 1.85rem; font-weight: 800; letter-spacing: -0.02em; color: #fff; }}
    .brand-meta {{ color: var(--text-muted); font-size: 0.85rem; margin-top: 0.2rem; }}

    .actions-bar {{ display: flex; gap: 0.75rem; flex-wrap: wrap; }}
    .btn {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.55rem 1.1rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s ease;
      text-decoration: none;
    }}
    .btn:hover {{ border-color: var(--primary); background: #132747; color: var(--primary); }}
    .btn-primary {{ background: rgba(0, 240, 255, 0.12); border-color: var(--primary); color: var(--primary); }}
    .btn-primary:hover {{ background: rgba(0, 240, 255, 0.25); }}

    /* KPI Grid */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }}
    .kpi-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.35rem 1.25rem;
      position: relative;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .kpi-card::after {{
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; height: 3px;
      background: var(--border);
    }}
    .kpi-card.grade::after {{ background: {grade_color}; }}
    .kpi-card.risk::after {{ background: {'#10b981' if summary.risk_score < 25 else '#ef4444'}; }}
    .kpi-card.vulns::after {{ background: {'#10b981' if summary.failed == 0 else '#ef4444'}; }}
    .kpi-card.defended::after {{ background: var(--primary); }}
    .kpi-card.controls::after {{ background: var(--success); }}

    .kpi-title {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-muted); font-weight: 700; }}
    .kpi-value {{ font-size: 2.35rem; font-weight: 900; margin: 0.4rem 0 0.2rem 0; line-height: 1; }}
    .kpi-subtext {{ font-size: 0.8rem; color: var(--text-muted); }}

    /* Charts Grid */
    .charts-grid {{
      display: grid;
      grid-template-columns: 1fr 1.35fr 1.35fr;
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }}
    @media (max-width: 1050px) {{
      .charts-grid {{ grid-template-columns: 1fr; }}
    }}
    .chart-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.35rem;
      display: flex;
      flex-direction: column;
    }}
    .chart-card h3 {{ font-size: 1rem; font-weight: 700; margin-bottom: 1rem; color: #fff; }}

    /* Interactive Table Section */
    .table-section {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 2.5rem;
    }}
    .table-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      margin-bottom: 1.25rem;
    }}
    .table-title {{ font-size: 1.25rem; font-weight: 800; display: flex; align-items: center; gap: 0.5rem; }}

    /* Filter Tabs */
    .filter-tabs {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
    .tab-btn {{
      background: var(--card-inner);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.45rem 0.9rem;
      border-radius: 8px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s ease;
    }}
    .tab-btn:hover {{ border-color: var(--primary); color: #fff; }}
    .tab-btn.active {{ background: var(--primary-dim); border-color: var(--primary); color: var(--primary); }}
    .tab-count {{
      background: rgba(255, 255, 255, 0.1);
      padding: 0.1rem 0.4rem;
      border-radius: 10px;
      font-size: 0.7rem;
    }}

    /* Search Bar */
    .search-box {{
      width: 100%;
      margin-bottom: 1.25rem;
      position: relative;
    }}
    .search-input {{
      width: 100%;
      background: var(--card-inner);
      border: 1px solid var(--border);
      color: #fff;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      font-size: 0.875rem;
      outline: none;
      transition: border-color 0.2s ease;
    }}
    .search-input:focus {{ border-color: var(--primary); box-shadow: 0 0 8px rgba(0, 240, 255, 0.2); }}

    /* Table Styling */
    .table-responsive {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; }}
    th, td {{ padding: 0.9rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.85rem; vertical-align: middle; }}
    th {{ background: #0a1628; color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 700; }}
    tr.data-row:hover {{ background: rgba(2, 132, 199, 0.08); }}

    /* Status & Severity Badges */
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.75rem;
      letter-spacing: 0.02em;
    }}
    .badge-fail {{ background: var(--danger-dim); color: #fca5a5; border: 1px solid #ef4444; }}
    .badge-pass {{ background: var(--success-dim); color: #86efac; border: 1px solid #10b981; }}
    .badge-uncertain {{ background: var(--warning-dim); color: #fde047; border: 1px solid #f59e0b; }}
    .badge-control {{ background: rgba(168, 85, 247, 0.15); color: #d8b4fe; border: 1px solid var(--purple); }}

    .badge-sev-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
    .badge-sev-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
    .badge-sev-medium {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
    .badge-sev-low {{ background: rgba(6, 182, 212, 0.2); color: #67e8f9; border: 1px solid #06b6d4; }}

    /* Expandable Row Details */
    details {{ cursor: pointer; }}
    details summary {{ list-style: none; outline: none; font-weight: 600; color: var(--primary); display: flex; align-items: center; gap: 0.4rem; }}
    details summary::-webkit-details-marker {{ display: none; }}
    .details-box {{
      background: #050a12;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      margin-top: 0.75rem;
    }}
    .code-box {{
      background: #02060d;
      border: 1px solid #14243b;
      padding: 0.65rem;
      border-radius: 6px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      white-space: pre-wrap;
      word-break: break-all;
      margin: 0.35rem 0 0.75rem 0;
      color: #e2e8f0;
    }}
    .remediation-box {{
      background: rgba(0, 240, 255, 0.08);
      border-left: 3px solid var(--primary);
      padding: 0.65rem 0.85rem;
      border-radius: 4px;
      font-size: 0.82rem;
      margin-top: 0.5rem;
      color: #bae6fd;
    }}

    /* Playbook Guidance Cards */
    .playbook-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }}
    .playbook-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.35rem;
    }}
    .playbook-card h4 {{ font-size: 1rem; font-weight: 700; color: var(--primary); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.5rem; }}
    .playbook-card p {{ font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.75rem; }}
    .playbook-card ul {{ padding-left: 1.2rem; font-size: 0.82rem; color: #cbd5e1; }}
    .playbook-card li {{ margin-bottom: 0.35rem; }}

    /* Toast Notification */
    #toast {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #0e2744;
      border: 1px solid var(--primary);
      color: #fff;
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 4px 14px rgba(0,0,0,0.5);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
      z-index: 9999;
    }}
    #toast.show {{ opacity: 1; }}

    /* Print View Optimization */
    @media print {{
      body {{ background: #fff; color: #000; padding: 0; }}
      .btn, .filter-tabs, .search-box, #toast {{ display: none !important; }}
      .kpi-card, .chart-card, .table-section, .playbook-card {{ border: 1px solid #ccc; background: #fff !important; color: #000 !important; }}
      th {{ background: #eee !important; color: #000 !important; }}
      .code-box {{ background: #f8f8f8 !important; color: #000 !important; border: 1px solid #ddd; }}
      .details-box {{ background: #fafafa !important; border-color: #ddd !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Executive Header -->
    <header>
      <div class="brand">
        <div class="brand-logo">🧬</div>
        <div class="brand-title">
          <h1>PromptShield Security Assessment</h1>
          <div class="brand-meta">
            Target: <strong>{summary.target_name}</strong> |
            Audit Executed: <strong>{summary.timestamp}</strong> |
            Avg Latency: <strong>{summary.avg_latency_ms} ms</strong>
          </div>
        </div>
      </div>
      <div class="actions-bar">
        <button class="btn btn-primary" onclick="window.print()">🖨️ Print / PDF Report</button>
        <button class="btn" onclick="downloadJson()">💾 Export Raw JSON</button>
        <button class="btn" onclick="copyExecutiveSummary()">📋 Copy Summary</button>
      </div>
    </header>

    <!-- Key Performance Indicators -->
    <div class="kpi-grid">
      <div class="kpi-card grade">
        <div class="kpi-title">Security Posture Grade</div>
        <div class="kpi-value" style="color: {grade_color};">{summary.letter_grade}</div>
        <div class="kpi-subtext">{grade_verdict}</div>
      </div>

      <div class="kpi-card risk">
        <div class="kpi-title">Vulnerability Risk Score</div>
        <div class="kpi-value" style="color: {'#10b981' if summary.risk_score < 25 else '#ef4444'};">
          {summary.risk_score}<span style="font-size: 1.1rem; color: var(--text-muted); font-weight: 500;"> / 100</span>
        </div>
        <div class="kpi-subtext">{summary.defense_score}% Overall Defense Integrity</div>
      </div>

      <div class="kpi-card vulns">
        <div class="kpi-title">Confirmed Vulnerabilities</div>
        <div class="kpi-value" style="color: {'#10b981' if summary.confirmed_vulnerabilities == 0 else '#ef4444'};">{summary.confirmed_vulnerabilities}</div>
        <div class="kpi-subtext">out of {summary.adversarial_probes} adversarial probes</div>
      </div>

      <div class="kpi-card defended">
        <div class="kpi-title">Attack Defense Rate</div>
        <div class="kpi-value" style="color: var(--primary);">{summary.attack_defense_rate_pct}%</div>
        <div class="kpi-subtext">{summary.adversarial_defended} / {summary.adversarial_probes} adversarial probes repelled</div>
      </div>

      <div class="kpi-card controls">
        <div class="kpi-title">Control Benchmarks</div>
        <div class="kpi-value" style="color: var(--success);">{summary.control_benchmarks_passed} / {summary.control_benchmarks_total}</div>
        <div class="kpi-subtext">{summary.control_pass_rate_pct}% operational integrity</div>
      </div>
    </div>

    <!-- Charts Grid -->
    <div class="charts-grid">
      <!-- Chart 1: Severity Doughnut -->
      <div class="chart-card">
        <h3>🚨 Exploit Severity Distribution</h3>
        <div style="position: relative; flex-grow: 1; min-height: 220px;">
          <canvas id="severityChart"></canvas>
        </div>
      </div>

      <!-- Chart 2: Category Bar Chart -->
      <div class="chart-card">
        <h3>🛡️ Defense Rate by Category</h3>
        <div style="position: relative; flex-grow: 1; min-height: 220px;">
          <canvas id="categoryChart"></canvas>
        </div>
      </div>

      <!-- Chart 3: OWASP Top 10 Reference Mapping -->
      <div class="chart-card">
        <h3>🌐 OWASP LLM Top 10 Reference Mapping</h3>
        <div style="position: relative; flex-grow: 1; min-height: 220px;">
          <canvas id="owaspChart"></canvas>
        </div>
      </div>
    </div>

    <!-- Interactive Table Section -->
    <div class="table-section">
      <div class="table-header">
        <div class="table-title">
          <span>🔍 Audit Test Suite & Findings Explorer</span>
        </div>
        <div class="filter-tabs">
          <button class="tab-btn active" onclick="setTab('all', this)">All Tests <span class="tab-count">{summary.total_cases}</span></button>
          <button class="tab-btn" onclick="setTab('fail', this)">Vulnerabilities <span class="tab-count" style="background: rgba(239, 68, 68, 0.3); color: #f87171;">{summary.confirmed_vulnerabilities}</span></button>
          <button class="tab-btn" onclick="setTab('pass', this)">Defended Attacks <span class="tab-count" style="background: rgba(16, 185, 129, 0.3); color: #86efac;">{summary.adversarial_defended}</span></button>
          <button class="tab-btn" onclick="setTab('uncertain', this)">Uncertain <span class="tab-count" style="background: rgba(245, 158, 11, 0.3); color: #fde047;">{summary.uncertain}</span></button>
          <button class="tab-btn" onclick="setTab('control', this)">Controls <span class="tab-count" style="background: rgba(168, 85, 247, 0.3); color: #d8b4fe;">{summary.control_benchmarks_total}</span></button>
        </div>
      </div>

      <div class="search-box">
        <input type="text" id="searchInput" class="search-input" placeholder="Quick search by Attack ID, Name, Category, OWASP, Prompt keywords, or Evidence..." onkeyup="filterRows()">
      </div>

      <div class="table-responsive">
        <table id="resultsTable">
          <thead>
            <tr>
              <th style="width: 100px;">Status</th>
              <th style="width: 110px;">ID</th>
              <th>Attack Name & OWASP Item</th>
              <th style="width: 90px;">Severity</th>
              <th style="width: 130px;">Category</th>
              <th style="width: 110px;">Action</th>
            </tr>
          </thead>
          <tbody>
"""

        for idx, res in enumerate(summary.results, 1):
            sev_val = res.severity.value
            status_val = res.status.value

            # Determine badge styling
            if res.is_control:
                status_badge = '<span class="badge badge-control">CONTROL (PASS)</span>'
                filter_type = "control"
            elif res.status == DetectionStatus.FAIL:
                status_badge = '<span class="badge badge-fail">VULNERABLE</span>'
                filter_type = "fail"
            elif res.status == DetectionStatus.PASS:
                status_badge = '<span class="badge badge-pass">DEFENDED</span>'
                filter_type = "pass"
            else:
                status_badge = '<span class="badge badge-uncertain">UNCERTAIN</span>'
                filter_type = "uncertain"

            sev_badge = f'<span class="badge badge-sev-{sev_val}">{sev_val.upper()}</span>'

            # Searchable aggregate text
            search_corpus = f"{res.attack_id} {res.attack_name} {res.category} {res.owasp.value} {res.prompt} {res.evidence}".lower()

            html += f"""
            <tr class="data-row" data-type="{filter_type}" data-search="{search_corpus}">
              <td>{status_badge}</td>
              <td><strong>{res.attack_id}</strong></td>
              <td>
                <div style="font-weight: 700; color: #fff;">{res.attack_name}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">{res.owasp.value}</div>
              </td>
              <td>{sev_badge}</td>
              <td><span style="font-size: 0.8rem; color: var(--text-muted); font-family: monospace;">{res.category}</span></td>
              <td>
                <details>
                  <summary>View Details</summary>
                  <div class="details-box">
                    <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700;">Injected Attack Payload:</div>
                    <div class="code-box">{res.prompt}</div>

                    <div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700;">Chatbot Model Response:</div>
                    <div class="code-box">{res.target_response}</div>

                    <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem;">
                      <div><strong style="color: var(--text-muted); font-size: 0.75rem;">DETECTOR:</strong> <span style="font-size: 0.8rem;">{res.detector_used} ({int(res.confidence * 100)}% conf)</span></div>
                      <div><strong style="color: var(--text-muted); font-size: 0.75rem;">EVIDENCE:</strong> <span style="font-size: 0.8rem; color: {'#f87171' if res.status == DetectionStatus.FAIL else '#86efac'};">{res.evidence}</span></div>
                    </div>

                    <div class="remediation-box">
                      <strong>💡 Recommended Mitigation:</strong><br>{res.recommended_mitigation}
                    </div>
                  </div>
                </details>
              </td>
            </tr>
"""

        html += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- Actionable Remediation Playbook -->
    <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 1rem; color: #fff;">🧬 Enterprise Remediation Playbook</h3>
    <div class="playbook-grid">
      <div class="playbook-card">
        <h4>🛡️ Layer 1: Input Guardrails</h4>
        <p>Pre-inference deterministic inspection to reject malicious tokens before model invocation.</p>
        <ul>
          <li>Deploy regex scanners for known injection patterns (e.g., "ignore previous instructions").</li>
          <li>Normalize encoding schemes (Base64 decoding, ROT13, unicode normalization).</li>
          <li>Enforce strict delimiter escaping (markdown headers, system XML tags, ChatML tokens).</li>
        </ul>
      </div>

      <div class="playbook-card">
        <h4>🔒 Layer 2: Output DLP & Canary Scrubbing</h4>
        <p>Post-inference Data Loss Prevention to stop sensitive token leaks before delivery.</p>
        <ul>
          <li>Plant high-entropy synthetic canary tokens in system prompts and audit for disclosure.</li>
          <li>Employ vector similarity and n-gram overlap checks against system prompt directives.</li>
          <li>Suppress responses violating internal privacy policy and replace with safe fallbacks.</li>
        </ul>
      </div>

      <div class="playbook-card">
        <h4>⚖️ Layer 3: Deterministic Transaction Enforcers</h4>
        <p>Hard boundary policy enforcement decoupling financial authority from LLM text generation.</p>
        <ul>
          <li>Never allow natural language chat to approve transactions exceeding authorized limits.</li>
          <li>Use hardcoded API gateways to enforce authorization thresholds (e.g., maximum refund $100).</li>
          <li>Require out-of-band multi-factor approval for managerial overrides or store credit.</li>
        </ul>
      </div>
    </div>
  </div>

  <div id="toast">Copied to clipboard!</div>

  <script>
    // Tab filtering logic
    let currentTab = 'all';
    function setTab(tabName, btnElem) {{
      currentTab = tabName;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btnElem.classList.add('active');
      filterRows();
    }}

    function filterRows() {{
      const query = document.getElementById('searchInput').value.toLowerCase().trim();
      const rows = document.querySelectorAll('#resultsTable tbody tr.data-row');

      rows.forEach(row => {{
        const rowType = row.getAttribute('data-type');
        const searchCorpus = row.getAttribute('data-search');

        const matchesTab = (currentTab === 'all') || (rowType === currentTab);
        const matchesQuery = (!query) || (searchCorpus.includes(query));

        if (matchesTab && matchesQuery) {{
          row.style.display = '';
        }} else {{
          row.style.display = 'none';
        }}
      }});
    }}

    // Export JSON
    function downloadJson() {{
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent('{escaped_json_string}');
      const dlAnchorElem = document.createElement('a');
      dlAnchorElem.setAttribute("href", dataStr);
      dlAnchorElem.setAttribute("download", "{summary.target_name.lower().replace(' ', '_')}_scan.json");
      dlAnchorElem.click();
      showToast("JSON report downloaded!");
    }}

    // Copy Summary to clipboard
    function copyExecutiveSummary() {{
      const summaryText = `PromptShield Security Audit Summary
Target: {summary.target_name}
Security Grade: {summary.letter_grade}
Vulnerability Risk Score: {summary.risk_score} / 100
Confirmed Vulnerabilities: {summary.confirmed_vulnerabilities}
Attack Defense Rate: {summary.attack_defense_rate_pct}% ({summary.adversarial_defended}/{summary.adversarial_probes} repelled)
Control Benchmarks: {summary.control_benchmarks_passed}/{summary.control_benchmarks_total} passed ({summary.control_pass_rate_pct}%)
Total Cases Evaluated: {summary.total_cases}`;
      navigator.clipboard.writeText(summaryText).then(() => {{
        showToast("Executive summary copied to clipboard!");
      }});
    }}

    function showToast(msg) {{
      const toast = document.getElementById('toast');
      toast.innerText = msg;
      toast.classList.add('show');
      setTimeout(() => {{ toast.classList.remove('show'); }}, 2500);
    }}

    // Chart 1: Exploit Severity Doughnut
    const ctxSev = document.getElementById('severityChart');
    if (ctxSev) {{
      new Chart(ctxSev, {{
        type: 'doughnut',
        data: {{
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{{
            data: [{crit_fails}, {high_fails}, {med_fails}, {low_fails}],
            backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#06b6d4'],
            borderColor: '#0e1e38',
            borderWidth: 2,
          }}]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          plugins: {{
            legend: {{ position: 'bottom', labels: {{ color: '#94a3b8', boxWidth: 12 }} }}
          }}
        }}
      }});
    }}

    // Chart 2: Category Defense Bar Chart
    const ctxCat = document.getElementById('categoryChart');
    if (ctxCat) {{
      new Chart(ctxCat, {{
        type: 'bar',
        data: {{
          labels: {json.dumps(categories)},
          datasets: [{{
            label: 'Defense Rate (%)',
            data: {json.dumps(pass_rates)},
            backgroundColor: '#00f0ff',
            borderRadius: 6,
          }}]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          scales: {{
            y: {{ beginAtZero: true, max: 100, ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1e3a5f' }} }},
            x: {{ ticks: {{ color: '#94a3b8', font: {{ size: 10 }} }}, grid: {{ display: false }} }}
          }},
          plugins: {{ legend: {{ display: false }} }}
        }}
      }});
    }}

    // Chart 3: OWASP Posture Horizontal Bar Chart
    const ctxOwasp = document.getElementById('owaspChart');
    if (ctxOwasp) {{
      new Chart(ctxOwasp, {{
        type: 'bar',
        data: {{
          labels: {json.dumps([k.split(':')[0] for k in owasp_labels])},
          datasets: [{{
            label: 'Pass Rate (%)',
            data: {json.dumps(owasp_rates)},
            backgroundColor: '#10b981',
            borderRadius: 6,
          }}]
        }},
        options: {{
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          scales: {{
            x: {{ beginAtZero: true, max: 100, ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1e3a5f' }} }},
            y: {{ ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }}, grid: {{ display: false }} }}
          }},
          plugins: {{ legend: {{ display: false }} }}
        }}
      }});
    }}
  </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

