
# ProcessSentinel

**A Windows Process Security Assistant powered by Python, PySide6, explainable security heuristics, and Groq AI.**

ProcessSentinel is a desktop application designed to help users inspect running Windows processes, identify potentially suspicious indicators, and understand security findings through AI-generated explanations.

It combines traditional rule-based analysis with AI-assisted investigation in a graphical interface. The application is designed for defensive security analysis and uses a read-only process-scanning approach.

> **Important:** ProcessSentinel is a security-assistance tool, not a malware detector or antivirus replacement. Its findings require verification.

## Features

- **Live process scanning:** Inspect running processes and collect available metadata, including process IDs, names, executable paths, CPU and memory usage, and parent process IDs.
- **Explainable heuristic analysis:** Apply transparent rules to identify potentially suspicious process characteristics.
- **AI-assisted explanations:** Use the Groq API to generate detailed explanations of selected processes and findings.
- **Dedicated AI workspace:** Review candidate processes and their explanations in a separate workspace.
- **Light and dark themes:** Switch the interface theme.
- **Read-only design:** Process inspection does not intentionally terminate processes or modify their execution.
- **Configuration-driven settings:** Configure application behavior through YAML.
- **Automated tests:** Test configuration loading, AI integration, application startup, and related components.

## Screenshots

Screenshots of the dashboard and AI Lab can be added here as the project develops.

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python |
| Desktop interface | PySide6 / Qt |
| Process inspection | psutil |
| Configuration | YAML / PyYAML |
| AI explanations | Groq API |
| API communication | Python urllib |
| Testing | pytest |
| Windows packaging | PyInstaller |

## Architecture

ProcessSentinel separates process collection, heuristic analysis, AI explanation, and the graphical interface into different modules.

```text
Windows Running Processes
          |
          v
    Process Scanner
          |
          v
    Scan Service
          |
          v
  Heuristic Analyzer
          |
          v
   Security Findings
          |
          v
     PySide6 GUI
          |
          v
    Groq AI Client
          |
          v
 Detailed Explanations
```

The AI explanation stage uses the Groq API when enabled and when a valid API key is available. AI output supplements the local analysis; it does not independently establish that a process is malicious.

## Project Structure

```text
ProcessSentinel/
├── config/
│   └── settings.yaml
├── src/
│   └── pc_security/
│       ├── main.py
│       ├── ai/
│       │   ├── groq_client.py
│       │   └── explanation_service.py
│       ├── core/
│       │   ├── config.py
│       │   ├── logging_config.py
│       │   └── scan_service.py
│       ├── scanner/
│       │   └── process_scanner.py
│       ├── security/
│       │   └── analyzer.py
│       └── ui/
│           └── main_window.py
├── tests/
├── .gitignore
├── pyproject.toml
└── README.md
```

The exact repository may contain additional files for packaging, testing, or development.

## Requirements

For development, you will need:

- Windows 10 or Windows 11
- A compatible Python version supported by the project's dependencies
- Git
- An internet connection for Groq AI explanations
- A Groq API key for AI features

The packaged Windows application does not require users to install Python separately.

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/Ibad2004/ProcessSentinel.git
cd ProcessSentinel
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, consult the official Python documentation for virtual environments rather than changing system security settings unnecessarily.

### 3. Install dependencies

If the project defines its dependencies in `pyproject.toml`, install the project and its declared dependencies using the appropriate project installation command. For an editable development installation, use:

```powershell
python -m pip install -e .
```

If development dependencies are defined separately, install those according to the project's configuration.

## Configure Groq AI

ProcessSentinel uses the Groq API to generate AI-assisted process explanations.

### 1. Create a Groq API key

Create an API key through the official Groq Console:

https://console.groq.com/

API access is subject to Groq account requirements, rate limits, model availability, and current pricing or usage policies.

### 2. Create a `.env` file

Create a file named `.env` in the project root:

```dotenv
GROQ_API_KEY=your_groq_api_key_here
```

Replace the placeholder with your own API key.

**Security precautions:**

- Never commit `.env` to Git.
- Never publish your API key in screenshots, source code, or logs.
- Do not distribute your personal API key with the executable.
- Users distributing or installing the application should configure their own credentials.

For a packaged Windows build, place the `.env` file beside `ProcessSentinel.exe` if the application is configured to load it from the executable directory.

## Configuration

Application settings are stored in `config/settings.yaml`.

Example configuration:

```yaml
app:
  name: "ProcessSentinel"
  environment: "development"

logging:
  level: "INFO"
  file: "logs/app.log"

security:
  read_only: true
  allow_process_termination: false

ai:
  provider: "groq"
  enabled: true
  model: "openai/gpt-oss-20b"
  timeout: 30
  max_tokens: 250
```

The AI model and token limit must be supported by the current Groq API configuration. The actual explanation length may also depend on application-level settings.

Keep `read_only` enabled and process termination disabled for the intended inspection-only workflow.

## Run ProcessSentinel

From the repository root, activate the virtual environment and run:

```powershell
$env:PYTHONPATH = "src"
python -m pc_security.main
```

The application should open its desktop interface.

Depending on the current implementation, the dashboard provides process scanning, heuristic findings, process details, and AI-assisted explanations.

## Understanding Security Findings

ProcessSentinel uses heuristic rules to identify characteristics that may deserve investigation.

Examples include:

- A Windows system process name whose executable path is outside expected Windows system directories.
- An executable located in a temporary directory.
- An executable located in the Downloads directory.
- Incomplete process metadata that limits the available evidence.

These indicators are not proof of malicious behavior. Legitimate applications may run from unusual directories, and malware may operate from normal-looking paths.

The heuristic score represents the application's rule-based assessment. It is **not a statistically calibrated probability of malware**.

A low score does not prove a process is safe, and a high score does not prove it is malicious.

## AI Explanation Workspace

The AI Lab provides additional context for selected processes.

AI-generated reports may include:

- Executive summary
- Process details
- Observed evidence
- Risk assessment
- Uncertainty and limitations
- Safe verification steps
- Conclusion

The AI service can explain supplied process metadata and heuristic findings, but it cannot independently verify every claim about a running process. Its conclusions may be incomplete or incorrect.

Treat AI reports as investigative assistance, not authoritative security verdicts. Verify important findings using trusted Windows tools and reputable security resources.

Only send process information to the external AI service when you are comfortable sharing that information with the configured provider. Avoid sending secrets or sensitive organizational data.

## Run Tests

Install pytest if it is not already installed:

```powershell
python -m pip install pytest
```

Run the test suite from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m pytest -q
```

A successful test run indicates that the tests passed; it does not guarantee that every runtime scenario or security finding is correct.

## Build the Windows Executable

Install PyInstaller:

```powershell
python -m pip install pyinstaller
```

Build the application from the project root:

```powershell
python -m PyInstaller --noconfirm --clean --onedir --windowed --name ProcessSentinel --paths src --add-data "config/settings.yaml;config" src\pc_security\main.py
```

The packaged application should be generated at:

```text
dist/
└── ProcessSentinel/
    ├── ProcessSentinel.exe
    └── ...
```

Launch `ProcessSentinel.exe` to run the desktop application.

For AI functionality, configure the user's own Groq API key in the location expected by the packaged application. Do not include personal API credentials in a distributed build.

The generated executable and supporting build files are local build artifacts and should not ordinarily be committed to the source repository.

## Security and Limitations

ProcessSentinel is intended for defensive inspection and learning.

- Process metadata may be incomplete because of Windows permissions or process protections.
- Heuristic rules can produce false positives and false negatives.
- AI explanations can contain errors or unsupported conclusions.
- Process names and file paths can be misleading or impersonated.
- The application does not replace antivirus software, endpoint detection and response tools, or professional incident response.
- Read-only process scanning does not mean the entire application is risk-free; API credentials, external API calls, dependencies, and displayed content still require appropriate security practices.

Always verify suspicious findings before taking action.

## Roadmap

Potential future improvements include:

- Additional explainable detection rules
- Improved evidence presentation and scan history
- More robust error handling and diagnostics
- Better packaging and distribution
- Additional automated tests
- Optional export of investigation reports

These are possible future enhancements, not claims that the features are already implemented.

## Contributing

Contributions, bug reports, and suggestions are welcome.

When submitting a change:

1. Describe the problem or improvement.
2. Keep changes focused and explainable.
3. Add or update tests where appropriate.
4. Never include API keys, `.env` files, or other secrets.
5. Document any new configuration options.

## License

No license is specified in this README. Check the repository for an existing `LICENSE` file before reusing, modifying, or distributing the project. If no license exists, consider adding one before accepting external contributions or distributing the software.

## Author

**Muhammad Ibad Ur Rehman**

GitHub: https://github.com/Ibad2004

Project repository: https://github.com/Ibad2004/ProcessSentinel
