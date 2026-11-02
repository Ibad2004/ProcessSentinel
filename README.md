# ProcessSentinel

**A read-only Windows process security assistant built with Python, PySide6, explainable rules, and optional Groq AI explanations.**

ProcessSentinel lists the programs running on your PC, checks them against transparent rules, and explains what it found in plain language. It is meant for learning and first-line investigation.

> **Important:** ProcessSentinel is a security-assistance tool, not a malware detector or antivirus replacement. Its findings are indicators that need verification, never proof of malware.

## Features

- **Live process scan**: name, PID, path, command line, user account, start time, parent process, CPU and memory.
- **Explainable rules**: each finding has a code, a severity, points, and a beginner-friendly explanation (see [Rules](#rules)).
- **Digital signature and SHA-256 checks**: shows whether each program file is signed, who signed it, and its SHA-256 hash.
- **VirusTotal hash lookup**: opens `https://www.virustotal.com/gui/file/<sha256>` in your browser. Only the hash is in the link; no file is ever uploaded.
- **Network tab**: open TCP/UDP connections per process (local and remote address, port, state), with search and a "Show only established" filter. Clicking a row opens that process.
- **Startup tab**: programs that start automatically from registry Run/RunOnce keys, Startup folders and scheduled tasks. Each one shows its signature status and any flags. Startup items are only scanned when you click **Scan startup items**.
- **History tab**: every scan is saved locally. You can see past scans, the processes in each one, and what appeared or disappeared compared with the scan before. Processes that are **new since the last scan** are highlighted, and "Show only new" filters to them.
- **Process tree view**: switch between a flat table and a parent/child tree.
- **HTML report export**: saves the current scan, flagged processes and AI explanations as a self-contained HTML file. User names are masked; the file has no scripts and loads nothing from the internet.
- **AI explanations (optional)**: Groq writes a structured report for a selected process, or for up to 10 processes with positive scores. If the rules flag nothing, nothing is sent automatically.
- **AI settings dialog**: set the Groq API key and model, test the connection, and apply changes without restarting.
- **Administrator banner**: a notice when ProcessSentinel runs without admin rights, because some details will be missing.
- **Light and dark themes**.
- **Read-only**: ProcessSentinel never stops, suspends, deletes, or changes processes, files, the registry, scheduled tasks, or system settings.

> **Tip:** run ProcessSentinel **as administrator** to see more. Without admin rights, Windows hides some executable paths, user accounts, signatures and network connections for system processes. ProcessSentinel never elevates itself.

## Screenshots

Screenshots of the dashboard, AI Lab, Network, Startup and History tabs can be added here.

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.11+ |
| Desktop interface | PySide6 / Qt |
| Process and network inspection | psutil |
| Signatures | PowerShell `Get-AuthenticodeSignature` (read-only) |
| Startup entries | `winreg` (read access only), Startup folders, `schtasks /query` |
| Scan history | SQLite (`sqlite3`) |
| Configuration | YAML / PyYAML, `.env` / python-dotenv |
| AI explanations | Groq API via Python `urllib` |
| Testing | pytest |
| Windows packaging | PyInstaller |

## Architecture

```text
Process scanner ─┐
Network scanner ─┼─> Scan service ──> Rule analyzer ──> Findings ──> Scan history (SQLite)
File inspector  ─┘        │                                               │
                          └──> AI explanation service (Groq, optional) ──>┴──> PySide6 UI
Startup / persistence scanner (on demand) ─────────────────────────────────────> Startup tab
```

The scanners only read information. The analyzer turns it into findings. The scan service ties the steps together and saves history. The UI shows everything and runs long work in background threads so the window stays responsive.

## Project Structure

```text
ProcessSentinel/
├── config/settings.yaml
├── data/                      # history.db is created here at runtime
├── logs/
├── src/pc_security/
│   ├── main.py                # entry point (python -m pc_security.main)
│   ├── ai/                    # groq_client.py, explanation_service.py
│   ├── core/                  # config, paths, scan_service, history, privacy,
│   │                          # settings_store, platform_info
│   ├── scanner/               # process_scanner, file_inspector,
│   │                          # network_scanner, persistence
│   ├── security/analyzer.py   # explainable rules
│   └── ui/                    # main_window and its tabs, dialogs and helpers
├── tests/
├── ProcessSentinel.spec       # PyInstaller build definition
├── .env.example
├── requirements.txt
└── pyproject.toml
```

## Requirements

- Windows 10 or 11. Signature, registry and scheduled task checks need Windows; on other systems they are skipped with a note.
- Python 3.11 or newer for development (the packaged app does not need Python).
- A Groq API key, only if you want AI explanations.

## Installation

```powershell
git clone https://github.com/Ibad2004/ProcessSentinel.git
cd ProcessSentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

`requirements.txt` installs the runtime dependencies (PyYAML, psutil, python-dotenv, PySide6) and pytest. You can also run `python -m pip install -e ".[dev]"`.

## Configure Groq AI (optional)

1. Create an API key in the [Groq Console](https://console.groq.com/).
2. Either open **⚙ AI settings** in the app and paste the key, or copy `.env.example` to `.env` beside the app and fill it in:

   ```dotenv
   GROQ_API_KEY=your_groq_api_key_here
   ```

The `.env` file is read from the project root in development and from the folder containing `ProcessSentinel.exe` in the packaged build. The AI settings dialog writes to that same file, keeps any other lines, and only ever shows the last 4 characters of the key.

Never commit `.env`, share your key in screenshots, or ship it inside a build.

## Configuration

`config/settings.yaml`:

```yaml
security:
  read_only: true
  allow_process_termination: false

ai:
  provider: "groq"
  enabled: true
  model: "openai/gpt-oss-20b"
  timeout: 30
  max_tokens: 2000   # reasoning models count thinking tokens toward this limit

history:
  max_scans: 50      # older scans are removed from data/history.db
```

The model can also be changed in **⚙ AI settings**. In a packaged build this writes `config/settings.yaml` beside the exe, which then takes priority over the bundled copy.

## Run ProcessSentinel

From the project root:

```powershell
$env:PYTHONPATH = "src"
python -m pc_security.main
```

Or with a `.bat` file in the project root:

```bat
@echo off
cd /d "%~dp0"
set PYTHONPATH=src
.venv\Scripts\python.exe -m pc_security.main
```

To see the most information, right-click the `.bat` file or `ProcessSentinel.exe` and choose **Run as administrator**.

## Rules

Each finding adds points, and the total is capped at 100. **0–19 = low, 20–49 = medium, 50+ = high.** Scores are rule-based indicators, not malware probabilities. Rules avoid double-counting: for example, an unsigned program in AppData gets one combined 30-point finding, not three separate ones.

### Process rules

| Code | Points | Severity | Meaning |
|---|---|---|---|
| `SYSTEM_NAME_UNUSUAL_PATH` | 35 | warning | A Windows system program name (e.g. svchost.exe) runs from outside the Windows system folders. |
| `EXECUTABLE_IN_TEMP` | 25 | warning | The program runs from a temporary folder. |
| `EXECUTABLE_IN_DOWNLOADS` | 15 | info | The program runs straight from Downloads. |
| `LOOKALIKE_SYSTEM_NAME` | 30 | warning | The name is one or two letters away from a Windows program name (e.g. svch0st.exe). |
| `SUSPICIOUS_PARENT_CHILD` | 40 | warning | Office or a web browser started PowerShell, cmd, wscript, mshta, rundll32 or similar. |
| `SUSPICIOUS_COMMAND_LINE` | 25–45 | warning | PowerShell with an encoded command, hidden window, DownloadString, IEX or FromBase64String (more indicators = more points). |
| `SYSTEM_PROCESS_WRONG_USER` | 40 | warning | A core Windows process (lsass, services, csrss…) runs as a normal user instead of a system account. |
| `SYSTEM_PROCESS_WRONG_PARENT` | 35 | warning | A core Windows process has an unexpected parent (e.g. lsass.exe not started by wininit.exe). |
| `EXECUTABLE_IN_USER_WRITABLE_DIR` | 10 | info | The program lives in AppData, LocalAppData, ProgramData or C:\Users\Public. |
| `UNSIGNED_IN_USER_WRITABLE_DIR` | 30 | warning | An unsigned program lives in one of those user-writable folders. |
| `SYSTEM_PROCESS_NOT_MICROSOFT_SIGNED` | 50 | warning | A Windows system program name is unsigned or signed by someone other than Microsoft. |
| `INVALID_SIGNATURE` | 45 | warning | The file's signature is broken or untrusted (e.g. the file changed after signing). |
| `UNSIGNED_EXECUTABLE` | 5 | info | The program has no digital signature. |
| `SCRIPT_HOST_WITH_NETWORK_ACTIVITY` | 15 | info | PowerShell, cmd, wscript, mshta, rundll32 or similar has outbound connections. |
| `UNSIGNED_WITH_NETWORK_ACTIVITY` | 10 | info | An unsigned program has outbound connections. |
| `MISSING_NAME` / `MISSING_PATH` | 0 | info | Windows did not reveal the name or path; this alone is not suspicious. |
| `NO_RULES_TRIGGERED` | 0 | info | No rule matched; this does not prove the process is safe. |

A signature status of **unknown** (the check could not finish) never adds points.

### Startup flags (Startup tab)

| Code | Points | Severity | Meaning |
|---|---|---|---|
| `STARTUP_EXECUTABLE_MISSING` | 10 | info | The entry points to a file that does not exist (often left over from uninstalled software). |
| `STARTUP_INVALID_SIGNATURE` | 45 | warning | The startup program's signature is invalid. |
| `STARTUP_UNSIGNED` | 10 | info | The startup program is not signed. |
| `STARTUP_IN_USER_WRITABLE_DIR` | 10 | info | The startup program lives in AppData, LocalAppData, ProgramData, Public, Temp or Downloads. |

Startup flags are shown only on the Startup tab and are never sent to the AI.

## AI Explanations

- **Scan + AI analysis** explains up to 10 processes whose rule score is above zero.
- If no process has a positive score, nothing is sent. The app shows *"No indicators found by the current rules. Select a process and click Explain to ask the AI about it."*
- **Explain selected process** always works for any process you choose.

Reports follow a fixed structure: summary, details, evidence, risk assessment, limitations, safe verification steps, and conclusion. The AI is told to treat all process data as untrusted, never to call a process malicious based only on a score, and never to recommend killing processes or deleting files. AI output can still be wrong; verify before acting.

## Privacy

**Sent to Groq**, only when you request an explanation:
- process name and PID, rule score and findings
- executable path and command line (shortened to about 500 characters)
- parent process and start time
- the account type: built-in accounts such as `NT AUTHORITY\SYSTEM` are shown, normal accounts become `<user>`
- signature status, signer and SHA-256
- outbound connection count, listening ports, and whether the process is new since the last scan

Your Windows user name is replaced with `<user>` in paths (`C:\Users\<user>\...`), command lines, the account field and finding text. `C:\Users\Public` and `C:\Users\Default` stay as they are. Remote IP addresses and startup entries are never sent.

**Stored locally in `data/history.db`** (beside the exe in the packaged build): for each scan, the time and counts, and for each process its PID, name, path, SHA-256, signature status, score, risk level and finding codes. Up to `history.max_scans` scans are kept. **Clear history** in the History tab deletes them. Nothing in the database is uploaded anywhere.

**VirusTotal**: the hash-lookup button only opens a web page for the SHA-256 in your browser. No file and no other data is uploaded.

**HTML reports** mask user names the same way as AI evidence. They are saved only where you choose.

## Run Tests

```powershell
$env:PYTHONPATH = "src"
python -m pytest -q
```

The tests use mocks only. They never inspect real processes, network connections, the registry, PowerShell or scheduled tasks, and they only write inside pytest's temporary folders. The suite is written to pass on Windows and Linux; Qt runs offscreen.

## Build the Windows Executable

```powershell
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --clean ProcessSentinel.spec
```

The app is created in `dist\ProcessSentinel\ProcessSentinel.exe`. `config/settings.yaml` is bundled; `data\` and `logs\` are created beside the exe on first start, and no history database is bundled.

> `--noconfirm` replaces the whole `dist\ProcessSentinel` folder. Back up any `.env` you placed beside the old exe first.

Quick check that a build works without opening a window or scanning:

```powershell
Start-Process dist\ProcessSentinel\ProcessSentinel.exe -ArgumentList --self-test -Wait -PassThru | Select-Object ExitCode
```

Exit code `0` means every module loaded and the configuration was found. `build/` and `dist/` are ignored by Git.

## Limitations

- Without administrator rights, some paths, users, signatures and connections are unavailable, so some rules cannot run.
- Rules are heuristics: legitimate software can trigger them (false positives), and malware can avoid them (false negatives).
- Signatures are checked with PowerShell; if it is blocked or times out, the status is **unknown**.
- Network data is a snapshot from the moment of the scan.
- "New since last scan" compares program files, not behaviour; a new program is not suspicious by itself.
- Startup scanning covers the Run/RunOnce keys, Startup folders and scheduled tasks. It does not cover services, drivers, WMI subscriptions or browser extensions.
- AI explanations can contain mistakes and only know the evidence they are given.
- ProcessSentinel does not replace antivirus, EDR, or professional incident response.

## Roadmap

Possible future work:

- Windows services and drivers in the Startup tab
- Optional local reputation lists (known-good hashes)
- Charts of risk levels across scan history

## Contributing

1. Describe the problem or improvement.
2. Keep changes read-only, focused and explainable.
3. Add or update tests (mocks only).
4. Never include API keys, `.env` files or personal scan data.
5. Document new configuration options.

## License

No license file is included yet. Add one before accepting external contributions or distributing the software.

## Author

**Muhammad Ibad Ur Rehman**

GitHub: https://github.com/Ibad2004

Project repository: https://github.com/Ibad2004/ProcessSentinel
