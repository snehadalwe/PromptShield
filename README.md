🧬 PromptShield
Python-Based AI Chatbot Prompt Injection Security Assessment Framework

PromptShield is a Python-based cybersecurity project designed to assess the security of AI chatbots and applications against prompt injection attacks.

It automatically executes security test cases against chatbot targets, analyzes their responses, identifies potential vulnerabilities, calculates risk scores, and generates security reports.

The framework supports both local simulated chatbot targets and authorized REST API endpoints, making it useful for learning and demonstrating AI application security testing.

Note: PromptShield is an educational security assessment framework. Its results are based on configured test cases and detection methods and should not be treated as a guarantee of complete AI system security.

🎯 Problem Statement

AI chatbots and large language models are increasingly being integrated into business applications, customer support systems, and enterprise workflows.

However, these applications can be exposed to prompt injection attacks, where specially crafted inputs attempt to manipulate the AI's instructions or bypass its intended security restrictions.

This may result in:

Disclosure of sensitive information.
Leakage of hidden system instructions.
Bypassing application policies.
Unexpected chatbot behavior.
Unauthorized actions in connected workflows.

PromptShield addresses this problem by providing an automated framework to evaluate chatbot responses against different prompt injection scenarios.

💡 Solution

PromptShield performs automated security assessments using a collection of predefined adversarial test cases.

The framework sends test inputs to a configured chatbot target, analyzes its responses using multiple detection techniques, and calculates a security risk score.

It evaluates areas such as:

Direct prompt injection
System prompt extraction
Policy bypass attempts
Delimiter injection
Encoding obfuscation
Multi-turn prompt injection
Sensitive information disclosure

The assessment results are classified using a risk score and security grade, helping developers understand potential weaknesses in their AI applications.

✨ Features
🧪 Automated prompt injection testing
🛡️ AI chatbot security assessment
🔍 Multiple attack-category test cases
📂 YAML-based test case library
🔌 Pluggable chatbot target adapters
🚦 Response analysis and detection
📊 Risk score calculation (0–100)
🏅 Security grading system (A–F)
⚖️ Baseline and hardened target comparison
📄 JSON, Markdown, and HTML report generation
📈 Interactive HTML security dashboard
💻 Command-line interface (CLI)
🧪 Automated test suite
🔐 Authorization confirmation before scanning
🏗️ Project Architecture
                       User
                         │
                         ▼
                  PromptShield CLI
                         │
                         ▼
                  Attack/Test Library
                       (YAML)
                         │
                         ▼
                  Target Adapters
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
        Demo Chatbot          REST API Target
              │                     │
              └──────────┬──────────┘
                         ▼
                  Response Analysis
                         │
                         ▼
                  Detection Engine
                         │
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
       Canary Detection       Refusal Detection
              │                     │
              └──────────┬──────────┘
                         ▼
                   Risk Scoring
                         │
                         ▼
                 Security Assessment
                         │
                         ▼
                  Report Generation
                         │
              ┌──────────┼──────────┐
              │          │          │
              ▼          ▼          ▼
             JSON     Markdown     HTML
                                    │
                                    ▼
                              Dashboard
📁 Project Structure
PromptShield/
│
├── attacks/                 # YAML-based attack test library
│
├── demo_target/             # Simulated chatbot targets
│
├── detectors/               # Response detection modules
│
├── reports/                 # Report generation modules
│
├── scoring/                 # Risk scoring and grading
│
├── targets/                 # Chatbot target adapters
│
├── tests/                   # Automated test cases
│
├── .github/
│   └── workflows/           # GitHub Actions workflow
│
├── cli.py                   # Command-line application
├── RESEARCH_FINDINGS.md     # Research and benchmark findings
├── .env.example             # Example environment configuration
├── .gitignore
└── README.md
⚙️ Technologies Used
Python – Core programming language
Pydantic – Data validation and models
PyYAML – YAML test case management
Requests – HTTP communication
Flask – Local demo server
Pytest – Automated testing
HTML / CSS / JavaScript – Dashboard interface
Chart.js – Dashboard visualizations
Git & GitHub – Version control
GitHub Actions – Workflow automation
🚀 Installation
1. Clone the repository
git clone https://github.com/snehadalwe/PromptShield.git
cd PromptShield
2. Create a virtual environment

Windows:

python -m venv .venv

Activate it:

.\.venv\Scripts\Activate.ps1
3. Install dependencies
pip install pydantic pyyaml requests pytest flask
▶️ Running the Local Demo

PromptShield includes simulated chatbot targets for security testing.

Start the local demo server:

python cli.py demo-server --port 5000

This allows you to experiment with the framework using local demo components.

🛡️ Running a Security Scan
1. Scan the weak demo chatbot
python cli.py scan --target demo-weak --agree-authorized --report all --output-dir reports/weak
2. Scan the hardened demo chatbot
python cli.py scan --target demo-hardened --agree-authorized --report all --output-dir reports/hardened
3. Test a specific attack category
python cli.py scan --target demo-weak --attacks policy_bypass --agree-authorized

PromptShield evaluates chatbot responses and generates a security assessment based on the configured test cases.

📊 Risk Assessment & Benchmark Results

PromptShield calculates a risk score between 0 and 100 and assigns a security grade from A to F.

The following results were recorded using the project's built-in synthetic demo targets.

Metric	Weak Demo	Hardened Demo
Total Test Cases	32	32
Adversarial Tests	25	25
Attacks Defended	5/25	25/25
Control Tests Passed	7/7	7/7
Risk Score	86.6	0.0
Security Grade	F	A
Findings	20	0

Result: In the local synthetic benchmark, the hardened demo achieved a 100% attack defense rate, compared with 20% for the weak demo.

These results demonstrate the framework's ability to distinguish between the two simulated chatbot configurations. They do not establish real-world security guarantees.

⚖️ Comparing Scan Results

PromptShield supports comparison between baseline and candidate scan reports.

Example:

python cli.py compare --baseline reports/weak/demo_weak_scan.json --candidate reports/hardened/demo_hardened_scan.json

This helps evaluate security improvements after modifying chatbot configurations or defensive controls.

📄 Report Generation

PromptShield supports three report formats:

Format	Purpose
JSON	Structured scan results
Markdown	Readable security assessment
HTML	Interactive security dashboard

The HTML dashboard provides visual summaries of scan results, findings, and security assessment details.

🧪 Running Tests

Run the automated test suite:

python -m pytest -v

The project previously achieved 41/41 passing tests in the local development environment.

🔐 Security Approach

PromptShield uses a combination of automated testing and response analysis techniques.

Its security assessment process includes:

Adversarial test case execution.
Benign control testing.
Canary-based detection.
Refusal classification.
Prompt leakage checks.
Rule-based response analysis.
Risk scoring and security grading.

This approach demonstrates important AI security concepts such as:

Prompt injection
AI red teaming
LLM application security
Security testing automation
Vulnerability assessment
Risk analysis
Security reporting
🔮 Future Improvements

Possible future improvements include:

Additional prompt injection test categories.
More chatbot and LLM integrations.
Advanced response analysis techniques.
Expanded benchmark datasets.
Improved dashboard visualizations.
Historical scan tracking.
Additional CI/CD integrations.
More detailed vulnerability remediation recommendations.
📸 Screenshots

Screenshots of the PromptShield dashboard, scan results, and comparison reports can be added here.

Example:

screenshots/
├── dashboard.png
├── weak-target-scan.png
├── hardened-target-scan.png
└── comparison-report.png
⚠️ Disclaimer

PromptShield is an educational cybersecurity project intended for learning, research, and authorized security assessments.

Only test AI systems you own or have explicit permission to assess.
Do not attempt to access confidential information without authorization.
Protect API keys and sensitive configuration details.
Synthetic benchmark results do not guarantee real-world security.
👩‍💻 Author

Snehal Dalwe

Cybersecurity Engineering Student

GitHub: https://github.com/snehadalwe

⭐ Project Goal

PromptShield demonstrates how Python programming, AI security concepts, automated testing, risk analysis, and reporting can be combined to build a practical AI chatbot security assessment framework.