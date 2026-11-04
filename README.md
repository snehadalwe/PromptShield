🧬 PromptShield: AI Chatbot Prompt Injection Security Assessment Framework

License: MIT (image) Python: 3.11+ (image) OWASP: LLM Top 10 (image) Demo Benchmark: Grade A (image) Automated Tests: 41/41 (image)

Author: Snehal (Third-year Cyber Security Engineering BTech)
Domain: LLM Application Security, Red-Teaming, Automated DAST for AI Systems
Framework Aligned: OWASP Top 10 for Large Language Model Applications

📌 1. What PromptShield Is

PromptShield is an automated prompt injection vulnerability scanning and red-teaming framework for AI chatbots and autonomous agents.

Similar to how traditional web vulnerability scanners audit for SQL Injection (SQLi) and Cross-Site Scripting (XSS), PromptShield performs automated security assessments of configured chatbot targets, evaluating resistance against Direct Prompt Injection (LLM01), Sensitive Information Disclosure (LLM02), System Prompt Leakage (LLM07), and Business Logic Bypasses (LLM09).

🌍 2. The Industry Problem It Addresses

Companies increasingly deploy AI assistants connected to internal enterprise data, customer support tools, and financial transaction pipelines. These chatbots rely on hidden instructions called a "system prompt" to maintain safety boundaries.

However, Large Language Models treat instructions and untrusted user input within a single contextual text stream. Without robust external guardrails, attackers manipulate conversational phrasing to override developer rules, leak confidential system instructions, and trigger unauthorized actions.

🎯 3. Why Prompt Injection Testing Matters

Unpredictable Token Boundaries: Probabilistic neural language models cannot enforce hard security boundaries without deterministic middleware.

Confidentiality Loss: Extracting system instructions frequently leaks internal proprietary guidelines, trade secrets, and hidden business logic.

Financial & Operational Impact: Exploited customer service chatbots have erroneously issued unauthorized refunds, modified product prices, and violated compliance terms.

DevSecOps Integration: As system prompts and model versions evolve, automated security regression testing is vital to prevent new vulnerabilities from reaching production.

⚡ 4. Main Features

Extensible Attack Library: Standardized YAML test cases covering direct injection, delimiter hijacking, base64/ROT13 obfuscation, multi-turn trust erosion, and policy bypasses.

Benign Control Benchmarking: Integrates legitimate control probes (e.g. compliant $50 refund requests under the $100 ceiling) to eliminate false positives and measure operational integrity.

Pluggable Target Adapters: Supports local simulated chatbots (WeakBot vs. HardenedBot), generic REST API endpoints (with URL validation and header masking), and OpenAI-compatible services.

Composite Detection Engine: Prioritizes synthetic canary token detection (CANARY-7F3A9), semantic refusal classification, and refusal-aware leak verification.

Dynamic Risk Scoring & Grade: Computes a custom 0–100 Vulnerability Risk Score, letter grades (A–F), and set-theoretic comparative delta reports (B∖C, B∩C, C∖B).

Interactive HTML Security Dashboard: Self-contained HTML report with Chart.js visualizations, interactive filter tabs, real-time search, print/PDF export, and remediation playbooks.

🏗️ 5. Architecture

                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�
                    â”‚      PromptShield CLI      â”‚
                    â”‚   (Authorization Check)    â”‚
                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                  â”‚
         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�
         â–¼                        â–¼                        â–¼
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�
â”‚  Attack Library  â”‚    â”‚  Target Adapter  â”‚    â”‚ Multi-Threading  â”‚
â”‚  (YAML / OWASP)  â”‚    â”‚ (REST/Demo/OAI)  â”‚    â”‚   Rate Limiter   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜    â””â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
         â”‚                       â”‚                       â”‚
         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                 â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�
                     â”‚  Composite Detector   â”‚
                     â”‚  - Canary Secret Scan â”‚
                     â”‚  - Control Validator  â”‚
                     â”‚  - Refusal Classifier â”‚
                     â”‚  - Fuzzy Prompt Leak  â”‚
                     â”‚  - Indicator Matcher  â”‚
                     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                 â–¼
                     â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”�
                     â”‚ Scoring & Reporting   â”‚
                     â”‚  - Risk Score (0-100) â”‚
                     â”‚  - Letter Grade (A-F) â”‚
                     â”‚  - HTML Security Dashboardâ”‚
                     â”‚  - JSON / Markdown    â”‚
                     â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜


promptshield/
â”œâ”€â”€ attacks/                  # Attack test suite mapped to OWASP LLM Top 10
â”‚   â”œâ”€â”€ models.py             # Pydantic schemas (AttackCase, Severity, OWASPMapping)
â”‚   â”œâ”€â”€ loader.py             # YAML audit library loader with ID & Category filtering
â”‚   â”œâ”€â”€ system_prompt_extraction.yaml # Canary and prompt disclosure probes + controls
â”‚   â”œâ”€â”€ direct_injection.yaml # Instruction override probes + controls
â”‚   â”œâ”€â”€ policy_bypass.yaml    # Business policy / refund limit probes + controls
â”‚   â”œâ”€â”€ encoding_obfuscation.yaml # Base64, ROT13, leetspeak, spaced tokens + controls
â”‚   â”œâ”€â”€ delimiter_injection.yaml  # Markdown header, ChatML & XML tag attacks + controls
â”‚   â””â”€â”€ multi_turn.yaml       # Context erosion & multi-turn dialog attacks + controls
â”œâ”€â”€ targets/                  # Pluggable target adapters
â”‚   â”œâ”€â”€ base.py               # Abstract BaseTarget interface & MessageTurn
â”‚   â”œâ”€â”€ demo_adapter.py       # In-memory benchmark adapter (Weak vs Hardened)
â”‚   â”œâ”€â”€ http_adapter.py       # Generic REST API chatbot adapter (URL validation & header masking)
â”‚   â””â”€â”€ openai_adapter.py     # OpenAI / vLLM / Ollama chat completions adapter (key masking)
â”œâ”€â”€ detectors/                # High-accuracy evaluation engines
â”‚   â”œâ”€â”€ base.py               # DetectionResult (PASS, FAIL, UNCERTAIN)
â”‚   â”œâ”€â”€ canary_detector.py    # Binary planted canary secret detector
â”‚   â”œâ”€â”€ system_prompt_detector.py # Content-aware leak detection (distinguishes discussion from leak)
â”‚   â”œâ”€â”€ rule_violation_detector.py # Indicator regex checks with refusal negation awareness
â”‚   â”œâ”€â”€ refusal_detector.py   # Explicit defensive refusal classifier
â”‚   â”œâ”€â”€ llm_judge_detector.py # LLM-as-a-Judge fallback
â”‚   â””â”€â”€ composite_detector.py # Prioritized multi-layer evaluation pipeline with control validation
â”œâ”€â”€ scoring/                  # Severity weighting and risk computation
â”‚   â”œâ”€â”€ models.py             # ScanSummary, CategorySummary, ComparisonReport
â”‚   â””â”€â”€ calculator.py         # 0-100 Risk Score, A-F Grades, and delta diffs (B\C, B∩C, C\B)
â”œâ”€â”€ reports/                  # Multi-format reporting engine
â”‚   â”œâ”€â”€ json_reporter.py      # Machine-readable output for CI/CD
â”‚   â”œâ”€â”€ markdown_reporter.py  # Formatted summaries for PRs & documentation
â”‚   â””â”€â”€ html_reporter.py      # Interactive HTML security dashboard with Chart.js
â”œâ”€â”€ demo_target/              # Safe practice & benchmark environment
â”‚   â”œâ”€â”€ system_prompt.py      # System directives & CANARY-7F3A9 secret
â”‚   â”œâ”€â”€ mock_engine.py        # Offline deterministic mock LLM emulator (Base64 & ROT13 support)
â”‚   â”œâ”€â”€ weak_bot.py           # Intentionally vulnerable chatbot
â”‚   â”œâ”€â”€ hardened_bot.py       # Defense-in-depth bot (Input Filter + Output DLP)
â”‚   â”œâ”€â”€ server.py             # Flask REST API endpoint (/chat)
â”‚   â””â”€â”€ client.py             # Interactive side-by-side terminal tester
â”œâ”€â”€ tests/                    # 41 automated unit, integration, and regression tests
â”œâ”€â”€ reports_output/           # Output directory for generated security reports
â”œâ”€â”€ cli.py                    # Unified CLI command runner with optional CI risk threshold gating
â”œâ”€â”€ RESEARCH_FINDINGS.md      # Security research write-up & empirical benchmark data
â””â”€â”€ README.md


💻 6. Technology Stack

Language: Python 3.11+ (Tested on Python 3.13)

Data Validation & Typing: pydantic>=2.0

Configuration & Payloads: pyyaml>=6.0

Networking & Adapters: requests>=2.28.0

Testing Framework: pytest>=8.0.0

Local Practice Server: flask>=3.0.0

Data Visualizations: Chart.js (embedded in single-file HTML reports)

⚙️ 7. Installation

Clone the repository and install dependencies in a virtual environment:

# Clone or navigate to the project directory
cd promptshield

# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install required dependencies
pip install pydantic pyyaml requests pytest flask

🔑 8. Setup & Configuration

For local practice testing, PromptShield requires no API keys; it runs fully deterministically using its offline MockLLMEngine.

If you choose to audit a live OpenAI-compatible LLM endpoint:

Copy the example environment file:

copy .env.example .env

Configure your API key and base URL:

OPENAI_API_KEY=your_actual_key_here
LLM_BASE_URL=https://api.openai.com/v1

(Note: .env is ignored by .gitignore and credentials are never checked into source control).

🤖 9. Running the Local Demo Chatbot

Test attacks interactively in your terminal before running automated batch scans:

# Interactive side-by-side terminal comparison (Weak vs Hardened)
python -m promptshield.demo_target.client  # Run from the directory containing the project folder

# Launch the local REST API server (Flask)
python cli.py demo-server --port 5000

🚀 10. Running a Security Scan via CLI

PromptShield enforces an ethical authorization check before executing scans:

# Scan Weak Target (Generates JSON, Markdown, and HTML reports in reports_output/)
python cli.py scan --target demo-weak --agree-authorized --report all --output-dir reports/weak

# Scan Hardened Target
python cli.py scan --target demo-hardened --agree-authorized --report all --output-dir reports/hardened

# Scan a specific attack category or specific attack ID
python cli.py scan --target demo-weak --attacks policy_bypass --agree-authorized
python cli.py scan --target demo-weak --attacks POL-004 --agree-authorized

# Scan an external custom REST chatbot
python cli.py scan --target http --url http://127.0.0.1:5000/chat --prompt-field message --agree-authorized

📊 11. Comparing Scan Results (Differential Benchmarking)

Quantify security posture improvement by comparing baseline vs. hardened scans:

python cli.py compare --baseline reports/weak/demo_weak_scan.json --candidate reports/hardened/demo_hardened_scan.json

Verified Local Demo Benchmark Results

Scope: These results come from 32 synthetic test cases run against PromptShield's built-in weak and hardened demo chatbots. They demonstrate the framework's behavior on these local demo targets; they are not a real-world certification or a guarantee about other AI systems.

Metric

Baseline Target (DemoTarget(WEAK))

Hardened Candidate (DemoTarget(HARDENED))

Differential Impact

Security Posture Grade

Grade F

Grade A

Improved in the local demo comparison

Vulnerability Risk Score

86.6 / 100

0.0 / 100

100.0% Risk Score Reduction in Local Demo

Total Test Cases

32

32

Full Suite Coverage

Adversarial Probes

25

25

Attack Test Vectors

Adversarial Probes Defended

5 / 25 (20.0%)

25 / 25 (100.0%)

+80.0% Absolute Defense Gain

Attack Defense Rate

20.0%

100.0%

Defended Adversarial Ratio

Confirmed Vulnerabilities

20

0

20 findings in weak demo / 0 in hardened demo

Control Benchmarks Passed

7 / 7 (100%)

7 / 7 (100%)

All 7 benign controls passed in both demo scans

Canary Secret Exfiltration

COMPROMISED (100% Leaked)

DEFENDED (0% Leaked)

No canary leakage observed in the hardened demo scan

📄 12. Generating Reports

When using --report all, PromptShield outputs three comprehensive artifacts in the specified output directory (default: reports_output/):

*_scan.json: Machine-readable structured findings containing all telemetry, latencies, and metadata for CI/CD pipelines.

*_report.md: GitHub-Flavored Markdown summary formatted for pull request comments and technical dossiers.

*_report.html: Self-contained interactive security dashboard.

📈 13. Dashboard Usage

The HTML report provides an interactive HTML security dashboard:

Instant Search: Search by attack ID, category, prompt keywords, or detector evidence.

Filter Tabs: View All Tests (32), Vulnerabilities (20), Defended Attacks (5), Uncertain (0), or Controls (7).

Chart.js Visualizations: Finding severity donut chart, category defense bar chart, and OWASP LLM Top 10 reference mapping.

Export Actions: Single-click " Print / PDF Report", " Export Raw JSON", and " Copy Summary" (with clipboard toast notifications).

Open the dashboard in your default browser:

Start-Process reports/weak/demo_weak_report.html
Start-Process reports/hardened/demo_hardened_report.html

🧪 14. Test Execution

PromptShield maintains a comprehensive 41-test automated suite covering adapters, detectors, scoring engines, demo targets, and CLI parsers:

# Run the complete test suite
python -m pytest tests/ -v

# Run collection check
python -m pytest tests/ --collect-only -q

(All 41 tests pass in approximately 1.0 second on Python 3.13).

ï¸� 15. Limitations & Security Scope

PromptShield is a security assessment, benchmarking, and red-teaming tool; it is not a guarantee that a chatbot is 100% secure.

Prompt injection is an open research challenge in artificial intelligence. While PromptShield tests against known vulnerability classes, novel obfuscations or zero-day jailbreaks may emerge. PromptShield should be used as one layer of a comprehensive defense-in-depth security strategy.

⚖️ 16. Ethical & Authorized Testing Disclaimer

PromptShield is developed STRICTLY for auditing chatbots that you own or have explicit, documented authorization to test.

Performing penetration testing or security assessments against systems without written permission is illegal and violates cybercrime statutes (including the Computer Fraud and Abuse Act and international equivalents). The authors and contributors assume no liability for misuse.