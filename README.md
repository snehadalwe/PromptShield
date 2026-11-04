🧬 PromptShield: AI Chatbot Prompt Injection Security Assessment Framework








Author: Snehal Dalwe
Education: Third-Year Cybersecurity Engineering Student
Domain: LLM Application Security, AI Red-Teaming, Automated Security Testing
Framework Alignment: OWASP Top 10 for Large Language Model Applications

📌 1. What PromptShield Is

PromptShield is a Python-based prompt injection vulnerability scanning and security assessment framework for AI chatbots and autonomous agents.

Similar to how traditional vulnerability scanners test web applications for SQL Injection (SQLi) and Cross-Site Scripting (XSS), PromptShield evaluates AI chatbot responses against different prompt injection scenarios.

It assesses areas such as:

Direct Prompt Injection
Sensitive Information Disclosure
System Prompt Leakage
Business Logic and Policy Bypasses

The framework runs automated security tests, evaluates chatbot responses, calculates risk scores, and generates detailed security reports.

🌍 2. The Industry Problem It Addresses

Organizations increasingly use AI assistants connected to internal databases, customer support platforms, business applications, and enterprise tools.

These AI systems rely on instructions to define their behavior and maintain security boundaries.

However, prompt injection can manipulate how an AI system interprets instructions and untrusted user input.

Potential consequences include:

Exposure of confidential information.
Disclosure of hidden system instructions.
Bypassing application policies.
Unexpected chatbot behavior.
Unauthorized actions in connected workflows.

PromptShield addresses this challenge by providing a structured way to assess chatbot behavior through repeatable security tests.

🎯 3. Why Prompt Injection Testing Matters
Instruction Manipulation: Untrusted input may attempt to override intended chatbot instructions.
Information Disclosure: Chatbots may reveal information that should remain protected.
Business Logic Bypass: AI assistants may fail to follow application-specific rules.
Security Regression: Changes to prompts, models, and application logic can introduce new weaknesses.
Continuous Assessment: Repeatable testing helps developers evaluate chatbot behavior throughout development.
⚡ 4. Main Features
Extensible Test Library: YAML-based test cases covering direct injection, delimiter injection, encoding obfuscation, multi-turn scenarios, and policy bypasses.
Benign Control Benchmarking: Includes legitimate requests to evaluate false positives and unnecessary refusals.
Pluggable Target Adapters: Supports local simulated chatbots, generic REST APIs, and OpenAI-compatible endpoints.
Composite Detection Engine: Combines canary detection, refusal classification, rule-based indicators, and prompt leakage checks.
Dynamic Risk Scoring: Calculates a 0–100 vulnerability risk score and assigns an A–F grade.
Comparative Analysis: Compares baseline and hardened scan results.
Multiple Report Formats: Generates JSON, Markdown, and HTML reports.
Interactive Security Dashboard: Provides visual summaries, filtering, search, and report export.
CLI Integration: Supports command-line execution and configurable risk thresholds for CI workflows.
🏗️ 5. Architecture

PromptShield follows a modular architecture consisting of test libraries, target adapters, response detectors, scoring components, and reporting modules.

                  ┌──────────────────────────┐
                  │      PromptShield CLI    │
                  │   Authorization Check   │
                  └────────────┬─────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
   │ Attack/Test  │    │   Target     │    │ Execution    │
   │   Library    │    │  Adapters    │    │  Controls    │
   │    (YAML)    │    │ REST / Demo  │    │              │
   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
          └───────────────────┼──────────────────┘
                              ▼
                   ┌─────────────────────┐
                   │ Composite Detector  │
                   │                     │
                   │ Canary Detection    │
                   │ Refusal Classifier  │
                   │ Prompt Leak Checks │
                   │ Rule Indicators     │
                   └──────────┬──────────┘
                              ▼
                   ┌─────────────────────┐
                   │ Scoring & Analysis  │
                   │                     │
                   │ Risk Score          │
                   │ Letter Grade        │
                   │ Comparison Results  │
                   └──────────┬──────────┘
                              ▼
                   ┌─────────────────────┐
                   │ Report Generation   │
                   │                     │
                   │ JSON / Markdown     │
                   │ HTML Dashboard      │
                   └─────────────────────┘
Project Directory Structure
PromptShield/
│
├── attacks/
│   ├── models.py
│   ├── loader.py
│   ├── system_prompt_extraction.yaml
│   ├── direct_injection.yaml
│   ├── policy_bypass.yaml
│   ├── encoding_obfuscation.yaml
│   ├── delimiter_injection.yaml
│   └── multi_turn.yaml
│
├── targets/
│   ├── base.py
│   ├── demo_adapter.py
│   ├── http_adapter.py
│   └── openai_adapter.py
│
├── detectors/
│   ├── base.py
│   ├── canary_detector.py
│   ├── system_prompt_detector.py
│   ├── rule_violation_detector.py
│   ├── refusal_detector.py
│   ├── llm_judge_detector.py
│   └── composite_detector.py
│
├── scoring/
│   ├── models.py
│   └── calculator.py
│
├── reports/
│   ├── json_reporter.py
│   ├── markdown_reporter.py
│   └── html_reporter.py
│
├── demo_target/
│   ├── system_prompt.py
│   ├── mock_engine.py
│   ├── weak_bot.py
│   ├── hardened_bot.py
│   ├── server.py
│   └── client.py
│
├── tests/
│
├── reports_output/
│
├── cli.py
├── RESEARCH_FINDINGS.md
├── .env.example
├── .gitignore
└── README.md
💻 6. Technology Stack
Technology	Purpose
Python 3.11+	Core programming language
Pydantic	Data validation and models
PyYAML	YAML test case loading
Requests	HTTP communication
Flask	Local demo server
Pytest	Automated testing
Chart.js	Dashboard visualizations
HTML/CSS/JavaScript	Interactive reporting dashboard
Git & GitHub	Version control and project hosting
GitHub Actions	Automated CI workflow
⚙️ 7. Installation
Step 1: Clone the repository
git clone https://github.com/snehadalwe/PromptShield.git
cd PromptShield
Step 2: Create a virtual environment

Windows PowerShell:

python -m venv .venv
.venv\Scripts\Activate.ps1
Step 3: Install dependencies
python -m pip install --upgrade pip
pip install pydantic pyyaml requests pytest flask
🔑 8. Setup & Configuration

PromptShield's built-in demo environment works without external API keys.

For testing an authorized OpenAI-compatible endpoint:

Copy the example environment file.
Copy-Item .env.example .env
Configure the environment variables supported by your adapter.

Example:

OPENAI_API_KEY=your_api_key
LLM_BASE_URL=https://api.openai.com/v1

Security Note: Never upload API keys, passwords, or other credentials to GitHub. Keep .env excluded through .gitignore.

🤖 9. Running the Local Demo Chatbot

PromptShield includes simulated chatbot targets for local testing.

Start the demo server
python cli.py demo-server --port 5000

The local demo environment allows you to experiment with chatbot security assessments without targeting an external production system.

🚀 10. Running a Security Scan via CLI

PromptShield includes an authorization confirmation requirement before scanning targets.

Scan the weak demo target
python cli.py scan --target demo-weak --agree-authorized --report all --output-dir reports/weak
Scan the hardened demo target
python cli.py scan --target demo-hardened --agree-authorized --report all --output-dir reports/hardened
Scan a particular attack category
python cli.py scan --target demo-weak --attacks policy_bypass --agree-authorized
Scan a particular test case
python cli.py scan --target demo-weak --attacks POL-004 --agree-authorized
Scan an authorized REST chatbot
python cli.py scan --target http --url http://127.0.0.1:5000/chat --prompt-field message --agree-authorized
📊 11. Comparing Scan Results

PromptShield supports differential benchmarking between baseline and candidate scan results.

Example:

python cli.py compare --baseline reports/weak/demo_weak_scan.json --candidate reports/hardened/demo_hardened_scan.json
Verified Local Demo Benchmark Results

The following results were recorded using 32 synthetic test cases against PromptShield's built-in weak and hardened demo chatbots.

Metric	Weak Demo	Hardened Demo
Security Grade	F	A
Risk Score	86.6/100	0.0/100
Total Test Cases	32	32
Adversarial Probes	25	25
Probes Defended	5/25 (20%)	25/25 (100%)
Control Tests Passed	7/7	7/7
Confirmed Findings	20	0
Attack Defense Rate	20%	100%

Benchmark Interpretation: The results represent the behavior of the project's local synthetic demo targets. They are not a real-world security certification or a guarantee that other AI systems will achieve the same results.

📄 12. Generating Reports

PromptShield supports three report formats.

Report	Description
JSON	Structured scan results for automated processing
Markdown	Readable security assessment summary
HTML	Interactive security dashboard

Generate all report formats using:

python cli.py scan --target demo-hardened --agree-authorized --report all

The output directory can be customized using --output-dir.

📈 13. Dashboard Usage

The HTML security dashboard provides an interactive view of scan results.

Dashboard Features
Instant Search: Search by attack ID, category, or finding details.
Filter Tabs: View all tests, vulnerabilities, defended attacks, uncertain results, and controls.
Visualizations: View severity and category-level summaries.
Export: Print reports, save as PDF through the browser, and export raw JSON.
Security Summary: Review the overall risk score and security grade.

Open a generated report in Windows PowerShell:

Start-Process reports/weak/demo_weak_report.html

The actual report filename depends on your scan output.

🧪 14. Test Execution

PromptShield includes automated tests covering its adapters, detectors, scoring logic, demo targets, and CLI functionality.

Run all tests
python -m pytest tests/ -v
Check test collection
python -m pytest tests/ --collect-only -q

Previously recorded result: 41/41 tests passed in the local development environment.

⚠️ 15. Limitations & Security Scope

PromptShield is a security assessment and benchmarking tool. It does not guarantee that an AI chatbot is completely secure.

Prompt injection remains an evolving security challenge.
A finite test library cannot identify every possible vulnerability.
Detection results depend on the target and detector configuration.
Synthetic demo results may differ from real-world AI application behavior.
A low risk score should not be treated as proof of security.

PromptShield should be used as one component of a broader security testing and defense-in-depth strategy.

⚖️ 16. Ethical & Authorized Testing Disclaimer

PromptShield is developed for educational purposes and authorized security assessments.

Test only systems you own or have explicit permission to assess.
Do not attempt to access confidential information without authorization.
Use synthetic information in demonstrations.
Protect API credentials and generated reports.
Follow applicable laws, organizational policies, and responsible disclosure practices.

The author assumes no responsibility for unauthorized use of this project.

👩‍💻 Author

Snehal Dalwe
Third-Year Cybersecurity Engineering Student

GitHub: @snehadalwe

⭐ If you find PromptShield interesting, explore the repository and its research findings!