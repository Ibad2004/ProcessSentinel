
"""Explainable, read-only rules for assessing process security indicators."""

import ntpath
import os
import re


# These Windows processes normally run from protected Windows directories.
WINDOWS_SYSTEM_PROCESSES = {
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
}

# Names that attackers commonly imitate with small spelling changes.
LOOKALIKE_TARGETS = WINDOWS_SYSTEM_PROCESSES | {
    "conhost.exe",
    "dllhost.exe",
    "explorer.exe",
    "rundll32.exe",
    "spoolsv.exe",
    "taskhostw.exe",
}

# Real Windows programs whose names happen to be a few letters away
# from a target above (for example lsaiso.exe vs lsass.exe).
LOOKALIKE_ALLOWLIST = {
    "dashost.exe",
    "iexplore.exe",
    "lsaiso.exe",
    "sihost.exe",
    "taskhost.exe",
    "taskhostex.exe",
}

OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

BROWSER_PROCESSES = {
    "brave.exe",
    "chrome.exe",
    "firefox.exe",
    "iexplore.exe",
    "msedge.exe",
    "opera.exe",
}

SCRIPT_HOST_PROCESSES = {
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
}

POWERSHELL_PROCESSES = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}

# (label shown to the user, pattern) - matched case-insensitively.
SUSPICIOUS_POWERSHELL_PATTERNS = [
    (
        "-EncodedCommand (script hidden as Base64 text)",
        re.compile(r"(?:^|\s)[-/]e(?:c|nc?[a-z]*)?(?=\s|$)", re.IGNORECASE),
    ),
    (
        "-WindowStyle Hidden (runs without a visible window)",
        re.compile(r"(?:^|\s)[-/]w[a-z]*\s+hidden\b", re.IGNORECASE),
    ),
    (
        "DownloadString (downloads text or code from the internet)",
        re.compile(r"downloadstring", re.IGNORECASE),
    ),
    (
        "IEX / Invoke-Expression (runs text as code)",
        re.compile(r"\biex\b|invoke-expression", re.IGNORECASE),
    ),
    (
        "FromBase64String (decodes hidden Base64 data)",
        re.compile(r"frombase64string", re.IGNORECASE),
    ),
]

# svchost.exe is intentionally excluded: Windows runs per-user service
# hosts (such as CDPUserSvc) under the signed-in user's account.
SYSTEM_ACCOUNT_PROCESSES = {
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
}

SYSTEM_ACCOUNTS = {"system", "local service", "network service"}

# Expected parent names. Only checked when the parent is still running and
# known; smss.exe instances that start csrss/wininit/winlogon normally exit.
EXPECTED_PARENTS = {
    "csrss.exe": {"smss.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "smss.exe": {"system", "smss.exe"},
    "svchost.exe": {"services.exe"},
    "wininit.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
}


def _system_root():
    """Return the Windows directory from %SystemRoot%."""
    return os.environ.get("SystemRoot") or r"C:\Windows"


def _normalize_path(path):
    """Normalize a Windows path for consistent comparisons."""
    if not isinstance(path, str) or not path.strip():
        return None

    return ntpath.normcase(ntpath.normpath(path.strip()))


def _is_inside_directory(path, directory):
    """Check whether a path is inside a directory, not just similarly named."""
    try:
        return ntpath.commonpath([path, directory]) == directory
    except ValueError:
        return False


def _normalize_name(value):
    """Lower-case a process name; return an empty string when unavailable."""
    return value.strip().lower() if isinstance(value, str) else ""


def _edit_distance(first, second):
    """Count single-letter insertions, deletions, or substitutions."""
    previous = list(range(len(second) + 1))

    for i, first_char in enumerate(first, start=1):
        current = [i]
        for j, second_char in enumerate(second, start=1):
            current.append(min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (first_char != second_char),
            ))
        previous = current

    return previous[-1]


def _strip_exe(name):
    return name[:-4] if name.endswith(".exe") else name


def _find_lookalike_target(normalized_name):
    """Return the system name this process imitates, or None."""
    if (
        not normalized_name
        or normalized_name in LOOKALIKE_TARGETS
        or normalized_name in LOOKALIKE_ALLOWLIST
    ):
        return None

    stem = _strip_exe(normalized_name)
    if len(stem) < 4:
        return None

    for target in sorted(LOOKALIKE_TARGETS):
        target_stem = _strip_exe(target)
        # Short names allow fewer changes, so "sms" is not matched to "smss".
        limit = 1 if len(target_stem) <= 5 else 2
        if 1 <= _edit_distance(stem, target_stem) <= limit:
            return target

    return None


def _account_name(username):
    """Return the account part of DOMAIN\\account, lower-cased."""
    return username.rsplit("\\", 1)[-1].strip().lower()


def _user_writable_directories():
    """Folders ordinary users (and malware running as them) can write to."""
    directories = {}

    for label, variable in (
        ("%APPDATA%", "APPDATA"),
        ("%LOCALAPPDATA%", "LOCALAPPDATA"),
        ("%PROGRAMDATA%", "PROGRAMDATA"),
    ):
        directory = _normalize_path(os.environ.get(variable, ""))
        if directory:
            directories[directory] = label

    public = _normalize_path(os.environ.get("PUBLIC") or r"C:\Users\Public")
    directories[public] = r"C:\Users\Public"

    return directories


def _add_finding(findings, code, severity, title, explanation, points=0):
    """Add a structured finding that can later be displayed in the UI."""
    findings.append({
        "code": code,
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "points": points,
    })


def analyze_process(process):
    """
    Assess one process using simple, explainable indicators.

    This function does not modify, stop, or delete any process.
    Missing metadata alone does not increase the risk score.

    Optional process fields used by the rules (missing fields skip a rule):
    parent_name, cmdline, username.
    """
    findings = []
    name = process.get("name")
    path = _normalize_path(process.get("exe_path"))
    normalized_name = _normalize_name(name)
    parent_name = process.get("parent_name")
    normalized_parent = _normalize_name(parent_name)
    cmdline = process.get("cmdline")
    username = process.get("username")

    # Missing information is a limitation, not proof of malicious activity.
    if not normalized_name:
        _add_finding(
            findings,
            "MISSING_NAME",
            "info",
            "Process name unavailable",
            "Windows or the operating system may not expose this process name.",
        )

    if path is None:
        _add_finding(
            findings,
            "MISSING_PATH",
            "info",
            "Executable path unavailable",
            "The scanner could not obtain an executable path. This alone is not suspicious.",
        )

    # Set when a location rule already scored the path, so rule 9 does
    # not count the same folder twice.
    location_scored = False

    # Rule 1: A Windows process with a familiar system name runs from
    # somewhere other than its usual system directories.
    if normalized_name in WINDOWS_SYSTEM_PROCESSES and path is not None:
        expected_directories = {
            _normalize_path(ntpath.join(_system_root(), "System32")),
            _normalize_path(ntpath.join(_system_root(), "SysWOW64")),
        }

        if ntpath.dirname(path) not in expected_directories:
            location_scored = True
            _add_finding(
                findings,
                "SYSTEM_NAME_UNUSUAL_PATH",
                "warning",
                "Windows process name with an unusual path",
                (
                    f"{name} normally runs from a Windows system directory, "
                    "but this executable is located elsewhere. Verify the file "
                    "before drawing conclusions."
                ),
                35,
            )

    # Rule 2: Executables running from temporary folders.
    # Software installers and legitimate applications can also use these folders.
    if path is not None:
        temp_roots = {
            _normalize_path(ntpath.join(_system_root(), "Temp")),
        }

        temp_env = _normalize_path(os.environ.get("TEMP", ""))
        tmp_env = _normalize_path(os.environ.get("TMP", ""))

        if temp_env:
            temp_roots.add(temp_env)
        if tmp_env:
            temp_roots.add(tmp_env)

        if any(
            _is_inside_directory(path, root)
            for root in temp_roots
            if root
        ):
            location_scored = True
            _add_finding(
                findings,
                "EXECUTABLE_IN_TEMP",
                "warning",
                "Executable running from a temporary folder",
                (
                    "Temporary folders are sometimes used by malware, but also "
                    "by legitimate installers and applications. Check the file "
                    "and its origin."
                ),
                25,
            )

    # Rule 3: Executables launched from the Downloads folder.
    # This is a weak indicator, so it receives a lower score.
    if path is not None:
        user_profile = _normalize_path(os.environ.get("USERPROFILE", ""))

        if user_profile:
            downloads_directory = ntpath.join(user_profile, "Downloads")

            if _is_inside_directory(path, downloads_directory):
                location_scored = True
                _add_finding(
                    findings,
                    "EXECUTABLE_IN_DOWNLOADS",
                    "info",
                    "Executable running from Downloads",
                    (
                        "Downloaded programs can be legitimate, but their source "
                        "should be verified before trusting them."
                    ),
                    15,
                )

    # Rule 4: A name that is almost, but not exactly, a Windows name.
    lookalike_target = _find_lookalike_target(normalized_name)
    if lookalike_target is not None:
        _add_finding(
            findings,
            "LOOKALIKE_SYSTEM_NAME",
            "warning",
            "Name looks like a Windows system process",
            (
                f"'{name}' differs from the Windows program "
                f"'{lookalike_target}' by only one or two letters. Malware "
                "sometimes uses near-identical names so it blends in. A "
                "legitimate program can also have a similar name by chance."
            ),
            30,
        )

    # Rule 5: Documents and web pages should rarely need a command shell.
    if (
        normalized_name in SCRIPT_HOST_PROCESSES
        and normalized_parent in OFFICE_PROCESSES | BROWSER_PROCESSES
    ):
        parent_kind = (
            "An Office application"
            if normalized_parent in OFFICE_PROCESSES
            else "A web browser"
        )
        _add_finding(
            findings,
            "SUSPICIOUS_PARENT_CHILD",
            "warning",
            "Unusual program started by Office or a browser",
            (
                f"{parent_kind} ({parent_name}) started {name}, a tool that "
                "can run commands or scripts. Malicious documents and web "
                "pages often do this to run their payload. Some add-ins and "
                "admin tools do it legitimately."
            ),
            40,
        )

    # Rule 6: PowerShell options frequently used to hide or download code.
    if isinstance(cmdline, str) and (
        normalized_name in POWERSHELL_PROCESSES
        or "powershell" in cmdline.lower()
        or "pwsh" in cmdline.lower()
    ):
        matched = [
            label
            for label, pattern in SUSPICIOUS_POWERSHELL_PATTERNS
            if pattern.search(cmdline)
        ]
        if matched:
            points = min(25 + 10 * (len(matched) - 1), 45)
            _add_finding(
                findings,
                "SUSPICIOUS_COMMAND_LINE",
                "warning",
                "PowerShell command line uses hiding or download options",
                (
                    "The command line contains: " + "; ".join(matched) + ". "
                    "Attackers use these options to hide what a script does "
                    "or to fetch code from the internet. IT management tools "
                    "sometimes use them too."
                ),
                points,
            )

    # Rule 7: Core Windows processes run under built-in service accounts.
    if (
        normalized_name in SYSTEM_ACCOUNT_PROCESSES
        and isinstance(username, str)
        and username.strip()
        and _account_name(username) not in SYSTEM_ACCOUNTS
    ):
        _add_finding(
            findings,
            "SYSTEM_PROCESS_WRONG_USER",
            "warning",
            "Windows system process running as a normal user",
            (
                f"{name} normally runs as SYSTEM, LOCAL SERVICE or NETWORK "
                f"SERVICE, but this one runs as '{username}'. A program "
                "pretending to be a Windows component would usually run as "
                "the signed-in user."
            ),
            40,
        )

    # Rule 8: Core Windows processes have well-known parents.
    expected_parents = EXPECTED_PARENTS.get(normalized_name)
    if expected_parents and normalized_parent and (
        normalized_parent not in expected_parents
    ):
        _add_finding(
            findings,
            "SYSTEM_PROCESS_WRONG_PARENT",
            "warning",
            "Windows system process has an unexpected parent",
            (
                f"{name} is normally started by "
                f"{' or '.join(sorted(expected_parents))}, but this one was "
                f"started by {parent_name}. Windows starts its own core "
                "processes in a fixed order, so a different parent deserves "
                "a closer look."
            ),
            35,
        )

    # Rule 9: Folders any user can write to. Many legitimate per-user apps
    # live here, so this is a weak indicator on its own. Temp, Downloads and
    # misplaced system names already have their own location rules.
    user_writable_label = None
    if path is not None and not location_scored:
        for directory, label in _user_writable_directories().items():
            if _is_inside_directory(path, directory):
                user_writable_label = label
                break

    if user_writable_label is not None:
        _add_finding(
            findings,
            "EXECUTABLE_IN_USER_WRITABLE_DIR",
            "info",
            "Executable in a user-writable folder",
            (
                f"This program runs from {user_writable_label}, a folder "
                "that normal user accounts can write to. Many legitimate apps "
                "install here (for example chat or update tools), but malware "
                "also uses these folders because no administrator rights are "
                "needed."
            ),
            10,
        )

    # Cap the score so its range remains predictable as rules are added.
    score = min(sum(finding["points"] for finding in findings), 100)

    if score >= 50:
        risk_level = "high"
    elif score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"

    if not findings:
        _add_finding(
            findings,
            "NO_RULES_TRIGGERED",
            "info",
            "No configured warning indicators found",
            (
                "The current rules did not identify a warning indicator. "
                "This does not guarantee that the process is safe."
            ),
        )

    return {
        "pid": process.get("pid"),
        "name": name,
        "exe_path": process.get("exe_path"),
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings,
        "parent_pid": process.get("parent_pid"),
        "parent_name": parent_name,
        "cmdline": cmdline,
        "username": username,
        "create_time": process.get("create_time"),
        "metadata_notes": list(process.get("metadata_notes") or []),
    }


def analyze_processes(processes):
    """Assess a collection of processes and return their findings."""
    return [analyze_process(process) for process in processes]
