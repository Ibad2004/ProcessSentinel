
"""Explainable, read-only rules for assessing process security indicators."""

import ntpath


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

WINDOWS_SYSTEM_DIRECTORIES = {
    r"\windows\system32",
    r"\windows\syswow64",
}


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
    """
    findings = []
    name = process.get("name")
    path = _normalize_path(process.get("exe_path"))
    normalized_name = name.strip().lower() if isinstance(name, str) else ""

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

    score = 0

    # Rule 1: A Windows process with a familiar system name runs from
    # somewhere other than its usual system directories.
    if normalized_name in WINDOWS_SYSTEM_PROCESSES and path is not None:
        expected_directories = {
            _normalize_path(r"C:\Windows\System32"),
            _normalize_path(r"C:\Windows\SysWOW64"),
        }

        if ntpath.dirname(path) not in expected_directories:
            points = 35
            score += points
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
                points,
            )

    # Rule 2: Executables running from temporary folders.
    # Software installers and legitimate applications can also use these folders.
    if path is not None:
        temp_roots = {
            _normalize_path(r"C:\Windows\Temp"),
        }

        temp_env = _normalize_path(__import__("os").environ.get("TEMP", ""))
        tmp_env = _normalize_path(__import__("os").environ.get("TMP", ""))

        if temp_env:
            temp_roots.add(temp_env)
        if tmp_env:
            temp_roots.add(tmp_env)

        if any(
            _is_inside_directory(path, root)
            for root in temp_roots
            if root
        ):
            points = 25
            score += points
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
                points,
            )

    # Rule 3: Executables launched from the Downloads folder.
    # This is a weak indicator, so it receives a lower score.
    if path is not None:
        user_profile = _normalize_path(
            __import__("os").environ.get("USERPROFILE", "")
        )

        if user_profile:
            downloads_directory = ntpath.join(user_profile, "Downloads")

            if _is_inside_directory(path, downloads_directory):
                points = 15
                score += points
                _add_finding(
                    findings,
                    "EXECUTABLE_IN_DOWNLOADS",
                    "info",
                    "Executable running from Downloads",
                    (
                        "Downloaded programs can be legitimate, but their source "
                        "should be verified before trusting them."
                    ),
                    points,
                )

    # Cap the score so its range remains predictable as rules are added.
    score = min(score, 100)

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
    }


def analyze_processes(processes):
    """Assess a collection of processes and return their findings."""
    return [analyze_process(process) for process in processes]
