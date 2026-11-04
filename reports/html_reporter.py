"""Interactive Cybersecurity SaaS HTML Report Generator for PromptShield.

Produces a self-contained, presentation-ready HTML dashboard featuring:
- Enterprise Dark Theme: Deep Midnight Indigo, Dark Navy, Electric Violet & Cyan accents
- Professional Sidebar navigation with brand emblem & live assessment status
- Executive Cybersecurity KPIs (Posture Grade, Risk Score Meter, Defense Rate, Controls)
- Embedded Chart.js Visualizations (Severity Donut, Category Defense, OWASP Top 10)
- Interactive tabbed & searchable vulnerability findings explorer
- In-depth payload inspection drawer with detector confidence & evidence analysis
- Actionable multi-layer enterprise remediation playbook cards
- Single-file design with inline SVG favicon and print/PDF export support
"""

import html
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

        # Grade color mapping (Electric Violet / Cyan / Vibrant status palette)
        grade_meta = {
            "A": {
                "color": "#45D9E8",
                "bg_glow": "rgba(69, 217, 232, 0.25)",
                "border": "rgba(69, 217, 232, 0.6)",
                "verdict": "Exceptional Hardening — Zero Critical Leaks Detected",
            },
            "B": {
                "color": "#9270FF",
                "bg_glow": "rgba(146, 112, 255, 0.25)",
                "border": "rgba(146, 112, 255, 0.6)",
                "verdict": "Resilient Posture — Low Residual Risk Under Attack",
            },
            "C": {
                "color": "#FFC837",
                "bg_glow": "rgba(255, 200, 55, 0.25)",
                "border": "rgba(255, 200, 55, 0.6)",
                "verdict": "Moderate Risk — Guardrail Gaps Detected in Policy/Prompt",
            },
            "D": {
                "color": "#FF8C42",
                "bg_glow": "rgba(255, 140, 66, 0.25)",
                "border": "rgba(255, 140, 66, 0.6)",
                "verdict": "High Vulnerability Exposure — Critical Guardrails Breached",
            },
            "F": {
                "color": "#FF4B72",
                "bg_glow": "rgba(255, 75, 114, 0.25)",
                "border": "rgba(255, 75, 114, 0.6)",
                "verdict": "Critically Vulnerable — Multiple Exploits Succeeded",
            },
        }

        grade_info = grade_meta.get(
            summary.letter_grade,
            {
                "color": "#A5A8C7",
                "bg_glow": "rgba(165, 168, 199, 0.2)",
                "border": "#34365C",
                "verdict": "Audit Completed",
            },
        )

        # Risk score bar color
        if summary.risk_score < 25.0:
            risk_color = "#45D9E8"
            risk_glow = "rgba(69, 217, 232, 0.4)"
            risk_label = "Low Risk Posture"
        elif summary.risk_score < 50.0:
            risk_color = "#FFC837"
            risk_glow = "rgba(255, 200, 55, 0.4)"
            risk_label = "Moderate Risk Posture"
        else:
            risk_color = "#FF4B72"
            risk_glow = "rgba(255, 75, 114, 0.4)"
            risk_label = "High Risk Exposure"

        # Severity breakdown of confirmed exploits
        crit_fails = sum(
            1
            for r in summary.results
            if r.status == DetectionStatus.FAIL
            and r.severity == Severity.CRITICAL
            and not r.is_control
        )
        high_fails = sum(
            1
            for r in summary.results
            if r.status == DetectionStatus.FAIL
            and r.severity == Severity.HIGH
            and not r.is_control
        )
        med_fails = sum(
            1
            for r in summary.results
            if r.status == DetectionStatus.FAIL
            and r.severity == Severity.MEDIUM
            and not r.is_control
        )
        low_fails = sum(
            1
            for r in summary.results
            if r.status == DetectionStatus.FAIL
            and r.severity == Severity.LOW
            and not r.is_control
        )

        # Categories for charts
        categories = list(summary.category_breakdown.keys())
        pass_rates = [summary.category_breakdown[c].pass_rate_pct for c in categories]

        # OWASP Top 10 breakdown
        owasp_labels = [k.split(":")[0] for k in summary.owasp_breakdown.keys()]
        owasp_rates = [summary.owasp_breakdown[k].pass_rate_pct for k in summary.owasp_breakdown.keys()]

        # Prepare JSON string for client-side download
        raw_json_string = summary.model_dump_json(indent=2)
        escaped_json_string = (
            raw_json_string.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "")
        )

        # Pre-build rows
        table_rows_html = []
        for res in summary.results:
            sev_val = res.severity.value
            status_val = res.status.value

            if res.is_control:
                status_badge = '<span class="badge badge-control"><span class="badge-dot"></span>CONTROL (PASS)</span>'
                filter_type = "control"
            elif res.status == DetectionStatus.FAIL:
                status_badge = '<span class="badge badge-fail"><span class="badge-dot"></span>VULNERABLE</span>'
                filter_type = "fail"
            elif res.status == DetectionStatus.PASS:
                status_badge = '<span class="badge badge-pass"><span class="badge-dot"></span>DEFENDED</span>'
                filter_type = "pass"
            else:
                status_badge = '<span class="badge badge-uncertain"><span class="badge-dot"></span>UNCERTAIN</span>'
                filter_type = "uncertain"

            sev_badge = f'<span class="badge badge-sev-{sev_val}">{sev_val.upper()}</span>'

            # Clean escaped text
            escaped_prompt = html.escape(res.prompt)
            escaped_response = html.escape(res.target_response)
            escaped_evidence = html.escape(res.evidence)
            escaped_mitigation = html.escape(res.recommended_mitigation)
            escaped_attack_name = html.escape(res.attack_name)
            escaped_owasp = html.escape(res.owasp.value)

            search_corpus = f"{res.attack_id} {res.attack_name} {res.category} {res.owasp.value} {res.prompt} {res.evidence}".lower()
            escaped_search = html.escape(search_corpus)

            evidence_color = "#FF4B72" if res.status == DetectionStatus.FAIL else "#45D9E8"

            row_html = f"""
            <tr class="data-row" data-type="{filter_type}" data-search="{escaped_search}">
              <td>{status_badge}</td>
              <td><span class="attack-id-pill">{res.attack_id}</span></td>
              <td>
                <div class="attack-title">{escaped_attack_name}</div>
                <div class="attack-owasp">{escaped_owasp}</div>
              </td>
              <td>{sev_badge}</td>
              <td><span class="category-pill">{res.category}</span></td>
              <td>
                <details class="row-details">
                  <summary class="details-toggle">
                    <span class="toggle-text">Inspect Proof</span>
                    <svg class="toggle-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
                  </summary>
                  <div class="details-panel">
                    <div class="details-field">
                      <div class="details-label">
                        <span>INJECTED ATTACK PAYLOAD</span>
                        <button class="copy-btn" onclick="copyText(`{escaped_prompt.replace('`', '\\`')}`, this)">Copy Payload</button>
                      </div>
                      <pre class="code-box payload">{escaped_prompt}</pre>
                    </div>

                    <div class="details-field">
                      <div class="details-label">
                        <span>CHATBOT MODEL RESPONSE</span>
                        <button class="copy-btn" onclick="copyText(`{escaped_response.replace('`', '\\`')}`, this)">Copy Output</button>
                      </div>
                      <pre class="code-box response">{escaped_response}</pre>
                    </div>

                    <div class="meta-strip">
                      <div class="meta-item">
                        <span class="meta-label">DETECTOR ENGINE</span>
                        <span class="meta-val">{res.detector_used} <span class="conf-pill">{int(res.confidence * 100)}% conf</span></span>
                      </div>
                      <div class="meta-item">
                        <span class="meta-label">TRIGGERED EVIDENCE</span>
                        <span class="meta-val" style="color: {evidence_color}; font-family: ui-monospace, monospace;">{escaped_evidence}</span>
                      </div>
                    </div>

                    <div class="mitigation-callout">
                      <div class="mitigation-title">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                        RECOMMENDED MITIGATION PLAYBOOK
                      </div>
                      <div class="mitigation-text">{escaped_mitigation}</div>
                    </div>
                  </div>
                </details>
              </td>
            </tr>"""
            table_rows_html.append(row_html)

        rendered_table_rows = "\n".join(table_rows_html)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🧬 PromptShield Enterprise Audit: {summary.target_name}</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🧬</text></svg>">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    /* =========================================================================
       PROMPTSHIELD ENTERPRISE DESIGN IDENTITY
       Palette:
         Primary Background: Deep Midnight Indigo (#101126)
         Secondary Background: Dark Navy (#181A35)
         Card Background: (#202344)
         Primary Accent: Electric Violet (#9270FF)
         Secondary Accent: Cyan (#45D9E8)
         Main Text: Soft White (#F4F5FF)
         Secondary Text: Muted Lavender (#A5A8C7)
         Borders: Subtle Indigo (#34365C)
       ========================================================================= */
    :root {{
      --bg-primary: #101126;
      --bg-secondary: #181A35;
      --card-bg: #202344;
      --card-inner: #151733;
      --code-bg: #0C0D1E;
      --border: #34365C;
      --border-focus: #4E5284;
      
      --accent-violet: #9270FF;
      --accent-violet-glow: rgba(146, 112, 255, 0.28);
      --accent-cyan: #45D9E8;
      --accent-cyan-glow: rgba(69, 217, 232, 0.25);
      
      --text-main: #F4F5FF;
      --text-muted: #A5A8C7;
      --text-dim: #7377A0;
      
      --sev-crit: #FF4B72;
      --sev-crit-glow: rgba(255, 75, 114, 0.25);
      --sev-high: #FF8C42;
      --sev-med: #FFC837;
      --sev-low: #45D9E8;
      --status-pass: #45D9E8;
      --status-pass-glow: rgba(69, 217, 232, 0.2);
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }}

    body {{
      background-color: var(--bg-primary);
      background-image: 
        radial-gradient(circle at 10% 15%, rgba(146, 112, 255, 0.08) 0%, transparent 45%),
        radial-gradient(circle at 90% 85%, rgba(69, 217, 232, 0.06) 0%, transparent 45%),
        radial-gradient(circle at 50% 50%, rgba(24, 26, 53, 0.5) 0%, transparent 100%);
      background-attachment: fixed;
      color: var(--text-main);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
    }}

    /* =========================================================================
       SIDEBAR NAVIGATION
       ========================================================================= */
    .sidebar {{
      width: 280px;
      min-height: 100vh;
      background: var(--bg-secondary);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0;
      left: 0;
      bottom: 0;
      z-index: 100;
      padding: 1.75rem 1.25rem;
      backdrop-filter: blur(12px);
    }}

    .sidebar-brand {{
      display: flex;
      align-items: center;
      gap: 0.85rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
      text-decoration: none;
    }}

    .brand-icon-wrapper {{
      width: 44px;
      height: 44px;
      border-radius: 12px;
      background: linear-gradient(135deg, rgba(146, 112, 255, 0.2), rgba(69, 217, 232, 0.2));
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.6rem;
      box-shadow: 0 0 15px var(--accent-violet-glow);
    }}

    .brand-text-col {{
      display: flex;
      flex-direction: column;
    }}

    .brand-title {{
      font-size: 1.25rem;
      font-weight: 800;
      letter-spacing: -0.01em;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.35rem;
    }}

    .brand-sub {{
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--accent-cyan);
      font-weight: 700;
    }}

    /* Assessment Target Status Box */
    .target-status-box {{
      background: var(--card-inner);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.85rem 1rem;
      margin-bottom: 1.75rem;
    }}

    .target-status-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.4rem;
    }}

    .target-status-title {{
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
      font-weight: 700;
    }}

    .target-live-pill {{
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.65rem;
      font-weight: 700;
      color: var(--accent-cyan);
      background: rgba(69, 217, 232, 0.12);
      border: 1px solid rgba(69, 217, 232, 0.3);
      padding: 0.15rem 0.5rem;
      border-radius: 20px;
    }}

    .pulse-dot {{
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--accent-cyan);
      box-shadow: 0 0 8px var(--accent-cyan);
    }}

    .target-name-val {{
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--text-main);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    /* Sidebar Navigation Links */
    .sidebar-menu {{
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      flex-grow: 1;
    }}

    .nav-header-label {{
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-dim);
      font-weight: 700;
      margin: 0.6rem 0.6rem 0.3rem 0.6rem;
    }}

    .nav-item {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.65rem 0.85rem;
      border-radius: 8px;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 600;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      border: 1px solid transparent;
    }}

    .nav-item:hover {{
      color: var(--text-main);
      background: rgba(146, 112, 255, 0.1);
      border-color: rgba(146, 112, 255, 0.25);
      transform: translateX(3px);
    }}

    .nav-item.active {{
      color: var(--text-main);
      background: linear-gradient(90deg, rgba(146, 112, 255, 0.18), rgba(69, 217, 232, 0.08));
      border-color: var(--accent-violet);
      box-shadow: 0 0 12px var(--accent-violet-glow);
    }}

    .nav-item svg {{
      stroke: currentColor;
      transition: transform 0.2s ease;
    }}

    .nav-item:hover svg {{
      transform: scale(1.1);
    }}

    /* Sidebar Footer */
    .sidebar-footer {{
      border-top: 1px solid var(--border);
      padding-top: 1rem;
      margin-top: auto;
    }}

    .compliance-pill {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 0.6rem 0.8rem;
      border-radius: 8px;
      font-size: 0.72rem;
      color: var(--text-muted);
    }}

    /* =========================================================================
       MAIN CONTENT CONTAINER
       ========================================================================= */
    .main-wrapper {{
      margin-left: 280px;
      flex-grow: 1;
      padding: 2rem 2.5rem;
      max-width: calc(100vw - 280px);
    }}

    @media (max-width: 1080px) {{
      .sidebar {{
        position: relative;
        width: 100%;
        min-height: auto;
        border-right: none;
        border-bottom: 1px solid var(--border);
      }}
      body {{
        flex-direction: column;
      }}
      .main-wrapper {{
        margin-left: 0;
        max-width: 100%;
        padding: 1.5rem 1rem;
      }}
    }}

    /* Top Navigation Bar */
    .top-navbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1.25rem;
      margin-bottom: 2rem;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid var(--border);
    }}

    .breadcrumb-area {{
      display: flex;
      flex-direction: column;
    }}

    .breadcrumb-trail {{
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-bottom: 0.25rem;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }}

    .breadcrumb-trail span {{
      color: var(--accent-cyan);
    }}

    .page-main-heading {{
      font-size: 1.65rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      color: var(--text-main);
    }}

    /* Action Buttons */
    .action-group {{
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
    }}

    .btn {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.55rem 1.15rem;
      border-radius: 8px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      text-decoration: none;
    }}

    .btn:hover {{
      border-color: var(--accent-violet);
      background: #272B52;
      color: #fff;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px var(--accent-violet-glow);
    }}

    .btn-primary {{
      background: linear-gradient(135deg, rgba(146, 112, 255, 0.2), rgba(69, 217, 232, 0.2));
      border-color: var(--accent-violet);
      color: var(--text-main);
    }}

    .btn-primary:hover {{
      background: linear-gradient(135deg, rgba(146, 112, 255, 0.35), rgba(69, 217, 232, 0.35));
      border-color: var(--accent-cyan);
      box-shadow: 0 4px 15px var(--accent-cyan-glow);
    }}

    /* =========================================================================
       EXECUTIVE SECURITY KPI CARDS
       ========================================================================= */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2.25rem;
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
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      backdrop-filter: blur(8px);
    }}

    .kpi-card:hover {{
      border-color: var(--border-focus);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
    }}

    .kpi-card::before {{
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: var(--border);
    }}

    .kpi-card.grade-card::before {{ background: {grade_info['color']}; box-shadow: 0 0 10px {grade_info['bg_glow']}; }}
    .kpi-card.risk-card::before {{ background: {risk_color}; box-shadow: 0 0 10px {risk_glow}; }}
    .kpi-card.vuln-card::before {{ background: {'#45D9E8' if summary.confirmed_vulnerabilities == 0 else '#FF4B72'}; }}
    .kpi-card.defense-card::before {{ background: var(--accent-violet); }}
    .kpi-card.control-card::before {{ background: var(--accent-cyan); }}

    .kpi-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.75rem;
    }}

    .kpi-label {{
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-weight: 700;
    }}

    .kpi-icon-pill {{
      width: 28px;
      height: 28px;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(146, 112, 255, 0.1);
      border: 1px solid rgba(146, 112, 255, 0.2);
    }}

    .grade-badge-display {{
      display: flex;
      align-items: baseline;
      gap: 0.75rem;
    }}

    .grade-circle {{
      width: 52px;
      height: 52px;
      border-radius: 50%;
      background: {grade_info['bg_glow']};
      border: 2px solid {grade_info['border']};
      color: {grade_info['color']};
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2.1rem;
      font-weight: 900;
      box-shadow: 0 0 16px {grade_info['bg_glow']};
    }}

    .kpi-big-value {{
      font-size: 2.1rem;
      font-weight: 900;
      line-height: 1.1;
      color: var(--text-main);
      margin-bottom: 0.35rem;
    }}

    .kpi-subtext {{
      font-size: 0.78rem;
      color: var(--text-muted);
    }}

    /* Risk Score Progress Bar */
    .risk-meter-bar {{
      width: 100%;
      height: 6px;
      background: var(--card-inner);
      border-radius: 3px;
      overflow: hidden;
      margin: 0.6rem 0 0.4rem 0;
      border: 1px solid var(--border);
    }}

    .risk-meter-fill {{
      height: 100%;
      width: {min(100.0, max(0.0, summary.risk_score))}%;
      background: {risk_color};
      box-shadow: 0 0 8px {risk_glow};
      border-radius: 3px;
    }}

    /* =========================================================================
       THREAT ANALYTICS & CHARTS GRID
       ========================================================================= */
    .section-title {{
      font-size: 1.25rem;
      font-weight: 800;
      margin-bottom: 1.25rem;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}

    .charts-grid {{
      display: grid;
      grid-template-columns: 1fr 1.35fr 1.35fr;
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }}

    @media (max-width: 1200px) {{
      .charts-grid {{
        grid-template-columns: 1fr;
      }}
    }}

    .chart-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.35rem;
      display: flex;
      flex-direction: column;
      position: relative;
      transition: all 0.25s ease;
    }}

    .chart-card:hover {{
      border-color: var(--border-focus);
    }}

    .chart-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }}

    .chart-title {{
      font-size: 0.95rem;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 0.45rem;
    }}

    .chart-tag {{
      font-size: 0.68rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      background: var(--card-inner);
      border: 1px solid var(--border);
      color: var(--accent-cyan);
    }}

    .chart-canvas-wrapper {{
      position: relative;
      flex-grow: 1;
      min-height: 230px;
    }}

    /* =========================================================================
       FINDINGS EXPLORER & VULNERABILITY TABLE
       ========================================================================= */
    .table-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 2.5rem;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    }}

    .table-top-controls {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      margin-bottom: 1.25rem;
    }}

    /* Filter Tabs */
    .tab-group {{
      display: flex;
      gap: 0.45rem;
      flex-wrap: wrap;
    }}

    .tab-btn {{
      background: var(--card-inner);
      border: 1px solid var(--border);
      color: var(--text-muted);
      padding: 0.45rem 0.85rem;
      border-radius: 8px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }}

    .tab-btn:hover {{
      border-color: var(--accent-violet);
      color: var(--text-main);
    }}

    .tab-btn.active {{
      background: rgba(146, 112, 255, 0.15);
      border-color: var(--accent-violet);
      color: var(--text-main);
      box-shadow: 0 0 10px var(--accent-violet-glow);
    }}

    .tab-count-pill {{
      background: rgba(255, 255, 255, 0.08);
      padding: 0.12rem 0.45rem;
      border-radius: 10px;
      font-size: 0.68rem;
    }}

    /* Search Box */
    .search-wrapper {{
      position: relative;
      width: 100%;
      margin-bottom: 1.25rem;
    }}

    .search-input {{
      width: 100%;
      background: var(--card-inner);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.75rem 1rem 0.75rem 2.5rem;
      border-radius: 8px;
      font-size: 0.85rem;
      outline: none;
      transition: all 0.2s ease;
    }}

    .search-input:focus {{
      border-color: var(--accent-cyan);
      box-shadow: 0 0 12px var(--accent-cyan-glow);
    }}

    .search-icon {{
      position: absolute;
      left: 0.85rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-dim);
      pointer-events: none;
    }}

    /* Responsive Table */
    .table-responsive {{
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--border);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }}

    th {{
      background: var(--card-inner);
      color: var(--text-muted);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
      padding: 0.85rem 1rem;
      border-bottom: 1px solid var(--border);
    }}

    td {{
      padding: 0.95rem 1rem;
      border-bottom: 1px solid var(--border);
      font-size: 0.84rem;
      vertical-align: middle;
      background: var(--card-bg);
    }}

    tr.data-row:hover td {{
      background: #25284D;
    }}

    /* Badges */
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.6rem;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.72rem;
      letter-spacing: 0.02em;
    }}

    .badge-dot {{
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
    }}

    .badge-fail {{
      background: rgba(255, 75, 114, 0.16);
      color: #FF708F;
      border: 1px solid rgba(255, 75, 114, 0.4);
    }}

    .badge-pass {{
      background: rgba(69, 217, 232, 0.14);
      color: var(--accent-cyan);
      border: 1px solid rgba(69, 217, 232, 0.4);
    }}

    .badge-uncertain {{
      background: rgba(255, 200, 55, 0.15);
      color: #FFD56B;
      border: 1px solid rgba(255, 200, 55, 0.4);
    }}

    .badge-control {{
      background: rgba(146, 112, 255, 0.15);
      color: #C0AEFF;
      border: 1px solid rgba(146, 112, 255, 0.4);
    }}

    .badge-sev-critical {{
      background: rgba(255, 75, 114, 0.2);
      color: #FF4B72;
      border: 1px solid #FF4B72;
    }}

    .badge-sev-high {{
      background: rgba(255, 140, 66, 0.2);
      color: #FF8C42;
      border: 1px solid #FF8C42;
    }}

    .badge-sev-medium {{
      background: rgba(255, 200, 55, 0.2);
      color: #FFC837;
      border: 1px solid #FFC837;
    }}

    .badge-sev-low {{
      background: rgba(69, 217, 232, 0.2);
      color: #45D9E8;
      border: 1px solid #45D9E8;
    }}

    .attack-id-pill {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-weight: 700;
      color: var(--accent-cyan);
      background: var(--card-inner);
      border: 1px solid var(--border);
      padding: 0.2rem 0.5rem;
      border-radius: 5px;
      font-size: 0.78rem;
    }}

    .category-pill {{
      font-family: ui-monospace, monospace;
      font-size: 0.76rem;
      color: var(--text-muted);
      background: var(--card-inner);
      padding: 0.2rem 0.45rem;
      border-radius: 4px;
      border: 1px solid var(--border);
    }}

    .attack-title {{
      font-weight: 700;
      color: var(--text-main);
      margin-bottom: 0.2rem;
    }}

    .attack-owasp {{
      font-size: 0.72rem;
      color: var(--text-muted);
    }}

    /* Row Expand Details */
    details.row-details {{
      cursor: pointer;
    }}

    summary.details-toggle {{
      list-style: none;
      outline: none;
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      color: var(--accent-violet);
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
      background: rgba(146, 112, 255, 0.1);
      border: 1px solid rgba(146, 112, 255, 0.25);
      transition: all 0.2s ease;
    }}

    summary.details-toggle::-webkit-details-marker {{
      display: none;
    }}

    summary.details-toggle:hover {{
      background: rgba(146, 112, 255, 0.2);
      border-color: var(--accent-violet);
      color: #fff;
    }}

    .toggle-icon {{
      transition: transform 0.2s ease;
    }}

    details[open] .toggle-icon {{
      transform: rotate(180deg);
    }}

    .details-panel {{
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.15rem;
      margin-top: 0.85rem;
      box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.4);
    }}

    .details-field {{
      margin-bottom: 0.85rem;
    }}

    .details-label {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin-bottom: 0.35rem;
    }}

    .copy-btn {{
      background: var(--card-inner);
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.65rem;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.15s ease;
    }}

    .copy-btn:hover {{
      color: var(--accent-cyan);
      border-color: var(--accent-cyan);
    }}

    .code-box {{
      background: #080914;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.8rem;
      white-space: pre-wrap;
      word-break: break-all;
      color: #E0E2F5;
      line-height: 1.5;
    }}

    .code-box.payload {{
      border-left: 3px solid var(--accent-violet);
    }}

    .code-box.response {{
      border-left: 3px solid var(--accent-cyan);
    }}

    .meta-strip {{
      display: flex;
      gap: 1.5rem;
      flex-wrap: wrap;
      background: var(--card-inner);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.6rem 0.85rem;
      margin-bottom: 0.85rem;
    }}

    .meta-item {{
      display: flex;
      flex-direction: column;
      gap: 0.15rem;
    }}

    .meta-label {{
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-dim);
    }}

    .meta-val {{
      font-size: 0.82rem;
      color: var(--text-main);
      font-weight: 600;
    }}

    .conf-pill {{
      font-size: 0.7rem;
      color: var(--accent-violet);
      background: rgba(146, 112, 255, 0.15);
      padding: 0.1rem 0.35rem;
      border-radius: 4px;
    }}

    .mitigation-callout {{
      background: rgba(146, 112, 255, 0.08);
      border: 1px solid rgba(146, 112, 255, 0.3);
      border-left: 3px solid var(--accent-violet);
      padding: 0.75rem 0.95rem;
      border-radius: 6px;
    }}

    .mitigation-title {{
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--accent-violet);
      display: flex;
      align-items: center;
      gap: 0.4rem;
      margin-bottom: 0.25rem;
    }}

    .mitigation-text {{
      font-size: 0.82rem;
      color: #E2E4FF;
      line-height: 1.5;
    }}

    /* =========================================================================
       REMEDIATION PLAYBOOK
       ========================================================================= */
    .playbook-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2.5rem;
    }}

    .playbook-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      position: relative;
      overflow: hidden;
      transition: all 0.25s ease;
    }}

    .playbook-card:hover {{
      border-color: var(--border-focus);
      transform: translateY(-2px);
    }}

    .playbook-card::before {{
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
    }}

    .playbook-card.layer-1::before {{ background: var(--accent-violet); }}
    .playbook-card.layer-2::before {{ background: var(--accent-cyan); }}
    .playbook-card.layer-3::before {{ background: #818CF8; }}

    .playbook-card h4 {{
      font-size: 1.05rem;
      font-weight: 700;
      color: var(--text-main);
      margin-bottom: 0.45rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    .playbook-card p {{
      font-size: 0.84rem;
      color: var(--text-muted);
      margin-bottom: 1rem;
    }}

    .playbook-card ul {{
      padding-left: 1.15rem;
      font-size: 0.82rem;
      color: #D3D6F0;
    }}

    .playbook-card li {{
      margin-bottom: 0.45rem;
      line-height: 1.45;
    }}

    /* Toast Notification */
    #toast {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: var(--card-bg);
      border: 1px solid var(--accent-violet);
      color: var(--text-main);
      padding: 0.85rem 1.35rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
      opacity: 0;
      transform: translateY(12px);
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      z-index: 9999;
      pointer-events: none;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    #toast.show {{
      opacity: 1;
      transform: translateY(0);
    }}

    /* Footer */
    .dashboard-footer {{
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      font-size: 0.78rem;
      color: var(--text-dim);
    }}

    /* Print View Optimization */
    @media print {{
      body {{
        background: #fff !important;
        color: #000 !important;
        display: block;
      }}
      .sidebar, .action-group, .search-wrapper, .tab-group, #toast {{
        display: none !important;
      }}
      .main-wrapper {{
        margin-left: 0 !important;
        padding: 0 !important;
        max-width: 100% !important;
      }}
      .kpi-card, .chart-card, .table-card, .playbook-card {{
        background: #fff !important;
        color: #000 !important;
        border: 1px solid #ccc !important;
        box-shadow: none !important;
      }}
      th {{
        background: #eee !important;
        color: #000 !important;
      }}
      td {{
        background: #fff !important;
        color: #000 !important;
      }}
      .code-box {{
        background: #f7f7f7 !important;
        color: #000 !important;
        border: 1px solid #ccc !important;
      }}
      .details-panel {{
        background: #fafafa !important;
        border: 1px solid #ccc !important;
      }}
    }}
  </style>
</head>
<body>

  <!-- =======================================================================
       SIDEBAR NAVIGATION COMPONENT
       ======================================================================= -->
  <aside class="sidebar">
    <a href="#" class="sidebar-brand">
      <div class="brand-icon-wrapper">🧬</div>
      <div class="brand-text-col">
        <div class="brand-title">PromptShield</div>
        <div class="brand-sub">AI Security Suite</div>
      </div>
    </a>

    <!-- Target Info Box -->
    <div class="target-status-box">
      <div class="target-status-header">
        <span class="target-status-title">AUDIT TARGET</span>
        <span class="target-live-pill"><span class="pulse-dot"></span>COMPLETED</span>
      </div>
      <div class="target-name-val" title="{summary.target_name}">{summary.target_name}</div>
    </div>

    <!-- Navigation Menu -->
    <nav class="sidebar-menu">
      <div class="nav-header-label">PLATFORM VIEWS</div>
      <a href="#overview" class="nav-item active">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
        <span>Security Posture</span>
      </a>
      <a href="#analytics" class="nav-item">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
        <span>Threat Analytics</span>
      </a>
      <a href="#findings" class="nav-item">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <span>Findings Explorer</span>
      </a>
      <a href="#playbook" class="nav-item">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        <span>Remediation Playbook</span>
      </a>
    </nav>

    <!-- Sidebar Bottom -->
    <div class="sidebar-footer">
      <div class="compliance-pill">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#45D9E8" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        <span>OWASP LLM 2025 Standard</span>
      </div>
    </div>
  </aside>

  <!-- =======================================================================
       MAIN AUDIT DASHBOARD WRAPPER
       ======================================================================= -->
  <main class="main-wrapper">
    <!-- Top Action Bar -->
    <header class="top-navbar" id="overview">
      <div class="breadcrumb-area">
        <div class="breadcrumb-trail">
          AUDIT ASSESSMENT &bull; <span>{summary.target_name}</span> &bull; {summary.timestamp}
        </div>
        <h1 class="page-main-heading">Chatbot Threat Assessment Dashboard</h1>
      </div>

      <div class="action-group">
        <button class="btn btn-primary" onclick="window.print()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
          Export PDF Report
        </button>
        <button class="btn" onclick="downloadJson()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Export Raw JSON
        </button>
        <button class="btn" onclick="copyExecutiveSummary()">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          Copy Summary
        </button>
      </div>
    </header>

    <!-- Executive KPI Grid -->
    <section class="kpi-grid">
      <!-- 1. Grade -->
      <div class="kpi-card grade-card">
        <div class="kpi-header">
          <span class="kpi-label">SECURITY GRADE</span>
          <div class="kpi-icon-pill">🧬</div>
        </div>
        <div class="grade-badge-display">
          <div class="grade-circle">{summary.letter_grade}</div>
          <div>
            <div style="font-weight: 800; font-size: 1.1rem; color: {grade_info['color']};">Tier {summary.letter_grade} Posture</div>
            <div class="kpi-subtext" style="line-height: 1.3;">{grade_info['verdict']}</div>
          </div>
        </div>
      </div>

      <!-- 2. Risk Score -->
      <div class="kpi-card risk-card">
        <div class="kpi-header">
          <span class="kpi-label">VULNERABILITY RISK SCORE</span>
          <div class="kpi-icon-pill" style="color: {risk_color};">⚡</div>
        </div>
        <div class="kpi-big-value" style="color: {risk_color};">
          {summary.risk_score}<span style="font-size: 1rem; color: var(--text-muted); font-weight: 500;"> / 100</span>
        </div>
        <div class="risk-meter-bar">
          <div class="risk-meter-fill"></div>
        </div>
        <div class="kpi-subtext">{summary.defense_score}% Overall Defense Integrity &bull; {risk_label}</div>
      </div>

      <!-- 3. Confirmed Vulnerabilities -->
      <div class="kpi-card vuln-card">
        <div class="kpi-header">
          <span class="kpi-label">CONFIRMED VULNERABILITIES</span>
          <div class="kpi-icon-pill" style="color: {'#45D9E8' if summary.confirmed_vulnerabilities == 0 else '#FF4B72'};">🚨</div>
        </div>
        <div class="kpi-big-value" style="color: {'#45D9E8' if summary.confirmed_vulnerabilities == 0 else '#FF4B72'};">
          {summary.confirmed_vulnerabilities}
        </div>
        <div class="kpi-subtext">out of {summary.adversarial_probes} adversarial probes ({summary.uncertain} uncertain)</div>
      </div>

      <!-- 4. Attack Defense Rate -->
      <div class="kpi-card defense-card">
        <div class="kpi-header">
          <span class="kpi-label">ATTACK DEFENSE RATE</span>
          <div class="kpi-icon-pill" style="color: var(--accent-violet);">🛡️</div>
        </div>
        <div class="kpi-big-value" style="color: var(--accent-violet);">
          {summary.attack_defense_rate_pct}%
        </div>
        <div class="kpi-subtext">{summary.adversarial_defended} / {summary.adversarial_probes} attacks neutralized</div>
      </div>

      <!-- 5. Control Benchmarks -->
      <div class="kpi-card control-card">
        <div class="kpi-header">
          <span class="kpi-label">CONTROL BENCHMARKS</span>
          <div class="kpi-icon-pill" style="color: var(--accent-cyan);">⚖️</div>
        </div>
        <div class="kpi-big-value" style="color: var(--accent-cyan);">
          {summary.control_benchmarks_passed} / {summary.control_benchmarks_total}
        </div>
        <div class="kpi-subtext">{summary.control_pass_rate_pct}% operational compliance (zero false positives)</div>
      </div>
    </section>

    <!-- Threat Analytics & Charts -->
    <section id="analytics" style="margin-bottom: 2.5rem;">
      <h2 class="section-title">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
        Threat Intelligence & Visual Analytics
      </h2>

      <div class="charts-grid">
        <!-- Chart 1: Exploit Severity Distribution -->
        <div class="chart-card">
          <div class="chart-header">
            <span class="chart-title">🚨 Exploit Severity</span>
            <span class="chart-tag">CVSS Weighted</span>
          </div>
          <div class="chart-canvas-wrapper">
            <canvas id="severityChart"></canvas>
          </div>
        </div>

        <!-- Chart 2: Category Defense Bar Chart -->
        <div class="chart-card">
          <div class="chart-header">
            <span class="chart-title">🛡️ Defense by Category</span>
            <span class="chart-tag">Repel Rate (%)</span>
          </div>
          <div class="chart-canvas-wrapper">
            <canvas id="categoryChart"></canvas>
          </div>
        </div>

        <!-- Chart 3: OWASP Top 10 Reference Mapping -->
        <div class="chart-card">
          <div class="chart-header">
            <span class="chart-title">🌐 OWASP LLM Top 10</span>
            <span class="chart-tag">Posture (%)</span>
          </div>
          <div class="chart-canvas-wrapper">
            <canvas id="owaspChart"></canvas>
          </div>
        </div>
      </div>
    </section>

    <!-- Findings Explorer Table -->
    <section id="findings" class="table-card">
      <div class="table-top-controls">
        <div class="section-title" style="margin-bottom: 0;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-violet)" stroke-width="2.5"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          Audit Test Suite & Findings Explorer
        </div>

        <div class="tab-group">
          <button class="tab-btn active" onclick="setTab('all', this)">
            All Tests <span class="tab-count-pill">{summary.total_cases}</span>
          </button>
          <button class="tab-btn" onclick="setTab('fail', this)">
            Vulnerabilities <span class="tab-count-pill" style="color: #FF708F;">{summary.confirmed_vulnerabilities}</span>
          </button>
          <button class="tab-btn" onclick="setTab('pass', this)">
            Defended Attacks <span class="tab-count-pill" style="color: var(--accent-cyan);">{summary.adversarial_defended}</span>
          </button>
          <button class="tab-btn" onclick="setTab('uncertain', this)">
            Uncertain <span class="tab-count-pill" style="color: #FFD56B;">{summary.uncertain}</span>
          </button>
          <button class="tab-btn" onclick="setTab('control', this)">
            Controls <span class="tab-count-pill" style="color: #C0AEFF;">{summary.control_benchmarks_total}</span>
          </button>
        </div>
      </div>

      <!-- Search Field -->
      <div class="search-wrapper">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <input type="text" id="searchInput" class="search-input" placeholder="Search by Attack ID, Name, OWASP item, payload phrase, detector or evidence..." onkeyup="filterRows()">
      </div>

      <!-- Results Table -->
      <div class="table-responsive">
        <table id="resultsTable">
          <thead>
            <tr>
              <th style="width: 120px;">Verdict</th>
              <th style="width: 110px;">Attack ID</th>
              <th>Attack Name & OWASP Classification</th>
              <th style="width: 100px;">Severity</th>
              <th style="width: 140px;">Category</th>
              <th style="width: 130px;">Investigation</th>
            </tr>
          </thead>
          <tbody>
{rendered_table_rows}
          </tbody>
        </table>
      </div>
    </section>

    <!-- Enterprise Remediation Playbook -->
    <section id="playbook" style="margin-bottom: 2.5rem;">
      <h2 class="section-title">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-violet)" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        Enterprise AI Remediation Playbook
      </h2>

      <div class="playbook-grid">
        <div class="playbook-card layer-1">
          <h4>
            <span style="color: var(--accent-violet);">🛡️ Layer 1:</span> Input Guardrails & Token Hygiene
          </h4>
          <p>Pre-inference deterministic inspection to reject malicious tokens before model invocation.</p>
          <ul>
            <li>Deploy regex scanners for known injection patterns (e.g., "ignore previous instructions").</li>
            <li>Normalize encoding schemes (Base64 decoding, ROT13, unicode normalization) before processing.</li>
            <li>Enforce strict delimiter escaping (markdown headers, system XML tags, ChatML tokens).</li>
          </ul>
        </div>

        <div class="playbook-card layer-2">
          <h4>
            <span style="color: var(--accent-cyan);">🔒 Layer 2:</span> Output DLP & Canary Scrubbing
          </h4>
          <p>Post-inference Data Loss Prevention to stop sensitive token leaks before client delivery.</p>
          <ul>
            <li>Plant high-entropy synthetic canary tokens in system prompts and audit for disclosure.</li>
            <li>Employ vector similarity and n-gram overlap checks against system prompt directives.</li>
            <li>Suppress responses violating internal privacy policy and replace with safe fallbacks.</li>
          </ul>
        </div>

        <div class="playbook-card layer-3">
          <h4>
            <span style="color: #818CF8;">⚖️ Layer 3:</span> Deterministic Financial & Policy Gates
          </h4>
          <p>Hard boundary policy enforcement decoupling business authority from LLM text generation.</p>
          <ul>
            <li>Never allow natural language chat to approve transactions exceeding authorized limits.</li>
            <li>Use hardcoded API gateways to enforce authorization thresholds (e.g., maximum refund $100).</li>
            <li>Require out-of-band multi-factor approval for managerial overrides or store credit.</li>
          </ul>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="dashboard-footer">
      <div>PromptShield Enterprise AI Security Platform &bull; Automated Red-Team Pentesting</div>
      <div>Target Response Latency: <strong>{summary.avg_latency_ms} ms avg</strong> &bull; Total Probes: <strong>{summary.total_cases}</strong></div>
    </footer>
  </main>

  <!-- Interactive Toast Notification -->
  <div id="toast">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
    <span id="toast-text">Action completed successfully</span>
  </div>

  <!-- Interactive Dashboard Controller -->
  <script>
    // Tab Filtering Logic
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

    // Copy Helper
    function copyText(text, btn) {{
      navigator.clipboard.writeText(text).then(() => {{
        const origText = btn.innerText;
        btn.innerText = "Copied!";
        showToast("Snippet copied to clipboard");
        setTimeout(() => {{ btn.innerText = origText; }}, 2000);
      }});
    }}

    // Export Raw JSON
    function downloadJson() {{
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent('{escaped_json_string}');
      const dlAnchorElem = document.createElement('a');
      dlAnchorElem.setAttribute("href", dataStr);
      dlAnchorElem.setAttribute("download", "{summary.target_name.lower().replace(' ', '_')}_scan.json");
      dlAnchorElem.click();
      showToast("Raw JSON report exported successfully");
    }}

    // Copy Executive Summary
    function copyExecutiveSummary() {{
      const summaryText = `PromptShield Enterprise Security Audit Summary
Target System: {summary.target_name}
Audit Timestamp: {summary.timestamp}
Security Posture Grade: {summary.letter_grade} ({grade_info['verdict']})
Vulnerability Risk Score: {summary.risk_score} / 100 ({summary.defense_score}% Defense Integrity)
Confirmed Vulnerabilities: {summary.confirmed_vulnerabilities}
Attack Defense Rate: {summary.attack_defense_rate_pct}% ({summary.adversarial_defended}/{summary.adversarial_probes} repelled)
Control Benchmarks: {summary.control_benchmarks_passed}/{summary.control_benchmarks_total} passed ({summary.control_pass_rate_pct}%)
Total Evaluated Cases: {summary.total_cases}`;

      navigator.clipboard.writeText(summaryText).then(() => {{
        showToast("Executive summary copied to clipboard!");
      }});
    }}

    // Toast Alert
    function showToast(msg) {{
      const toast = document.getElementById('toast');
      const textElem = document.getElementById('toast-text');
      textElem.innerText = msg;
      toast.classList.add('show');
      setTimeout(() => {{ toast.classList.remove('show'); }}, 2500);
    }}

    // =========================================================================
    // CHART.JS INITIALIZATION (Electric Violet & Cyan Cybersecurity Palette)
    // =========================================================================
    Chart.defaults.color = '#A5A8C7';
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

    // Chart 1: Severity Doughnut
    const ctxSev = document.getElementById('severityChart');
    if (ctxSev) {{
      new Chart(ctxSev, {{
        type: 'doughnut',
        data: {{
          labels: ['Critical', 'High', 'Medium', 'Low'],
          datasets: [{{
            data: [{crit_fails}, {high_fails}, {med_fails}, {low_fails}],
            backgroundColor: ['#FF4B72', '#FF8C42', '#FFC837', '#45D9E8'],
            borderColor: '#202344',
            borderWidth: 3,
            hoverOffset: 6
          }}]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          plugins: {{
            legend: {{
              position: 'bottom',
              labels: {{
                color: '#A5A8C7',
                boxWidth: 10,
                padding: 14,
                font: {{ size: 11, weight: '600' }}
              }}
            }},
            tooltip: {{
              backgroundColor: '#181A35',
              borderColor: '#34365C',
              borderWidth: 1,
              titleColor: '#F4F5FF',
              bodyColor: '#A5A8C7',
              padding: 10
            }}
          }},
          cutout: '72%'
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
            backgroundColor: '#9270FF',
            hoverBackgroundColor: '#45D9E8',
            borderRadius: 6,
          }}]
        }},
        options: {{
          responsive: true,
          maintainAspectRatio: false,
          scales: {{
            y: {{
              beginAtZero: true,
              max: 100,
              ticks: {{ color: '#A5A8C7', font: {{ size: 10 }} }},
              grid: {{ color: '#34365C' }}
            }},
            x: {{
              ticks: {{ color: '#A5A8C7', font: {{ size: 10 }} }},
              grid: {{ display: false }}
            }}
          }},
          plugins: {{
            legend: {{ display: false }},
            tooltip: {{
              backgroundColor: '#181A35',
              borderColor: '#9270FF',
              borderWidth: 1,
              titleColor: '#F4F5FF',
              bodyColor: '#A5A8C7',
              callbacks: {{
                label: function(ctx) {{ return ctx.parsed.y + '% Repelled'; }}
              }}
            }}
          }}
        }}
      }});
    }}

    // Chart 3: OWASP Top 10 Posture Chart
    const ctxOwasp = document.getElementById('owaspChart');
    if (ctxOwasp) {{
      new Chart(ctxOwasp, {{
        type: 'bar',
        data: {{
          labels: {json.dumps(owasp_labels)},
          datasets: [{{
            label: 'Posture Score (%)',
            data: {json.dumps(owasp_rates)},
            backgroundColor: '#45D9E8',
            hoverBackgroundColor: '#9270FF',
            borderRadius: 6,
          }}]
        }},
        options: {{
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          scales: {{
            x: {{
              beginAtZero: true,
              max: 100,
              ticks: {{ color: '#A5A8C7', font: {{ size: 10 }} }},
              grid: {{ color: '#34365C' }}
            }},
            y: {{
              ticks: {{ color: '#A5A8C7', font: {{ size: 10 }} }},
              grid: {{ display: false }}
            }}
          }},
          plugins: {{
            legend: {{ display: false }},
            tooltip: {{
              backgroundColor: '#181A35',
              borderColor: '#45D9E8',
              borderWidth: 1,
              titleColor: '#F4F5FF',
              bodyColor: '#A5A8C7',
              callbacks: {{
                label: function(ctx) {{ return ctx.parsed.x + '% Pass Rate'; }}
              }}
            }}
          }}
        }}
      }});
    }}
  </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path
