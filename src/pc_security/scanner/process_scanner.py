
"""Read-only scanner for collecting Windows process information."""

import subprocess
import time

import psutil


PROCESS_ATTRIBUTES = [
    "pid",
    "name",
    "exe",
    "memory_info",
    "ppid",
    "cmdline",
    "username",
    "create_time",
]


def _normalize_text(value):
    """Convert empty strings and whitespace-only strings to None."""
    if isinstance(value, str):
        return value.strip() or None

    return value


def _format_cmdline(cmdline):
    """Join a psutil argument list into one Windows command-line string."""
    if not cmdline:
        return None

    if isinstance(cmdline, str):
        return _normalize_text(cmdline)

    try:
        return _normalize_text(subprocess.list2cmdline(cmdline))
    except TypeError:
        return _normalize_text(" ".join(str(part) for part in cmdline))


def _read_process_attributes(process):
    """Read attributes; denied fields become None instead of dropping the process."""
    try:
        return process.as_dict(attrs=PROCESS_ATTRIBUTES, ad_value=None)
    except psutil.AccessDenied:
        # as_dict normally substitutes ad_value, but keep the process
        # visible even if a platform raises for the whole call.
        return {"pid": getattr(process, "pid", None)}


def _collect_process_info(process):
    """Collect metadata for one process without modifying it."""
    try:
        info = _read_process_attributes(process)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None

    memory_info = info.get("memory_info")
    memory_mb = None

    if memory_info is not None:
        memory_mb = round(
            memory_info.rss / (1024 * 1024),
            2,
        )

    name = _normalize_text(info.get("name"))
    exe_path = _normalize_text(info.get("exe"))
    cmdline = _format_cmdline(info.get("cmdline"))
    username = _normalize_text(info.get("username"))
    create_time = info.get("create_time")

    notes = []

    if name is None:
        notes.append("Process name unavailable")

    if exe_path is None:
        notes.append("Executable path unavailable")

    if memory_info is None:
        notes.append("Memory information unavailable")

    if info.get("ppid") is None:
        notes.append("Parent process ID unavailable")

    if cmdline is None:
        notes.append("Command line unavailable")

    if username is None:
        notes.append("User account unavailable")

    if create_time is None:
        notes.append("Start time unavailable")

    try:
        cpu_percent = process.cpu_percent(interval=None)
        cpu_percent = round(cpu_percent, 2)
    except (
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
        psutil.AccessDenied,
    ):
        cpu_percent = None
        notes.append("CPU information unavailable")

    return {
        "pid": info.get("pid"),
        "name": name,
        "exe_path": exe_path,
        "cpu_percent": cpu_percent,
        "memory_mb": memory_mb,
        "parent_pid": info.get("ppid"),
        "parent_name": None,
        "cmdline": cmdline,
        "username": username,
        "create_time": create_time,
        "metadata_notes": notes,
    }


def _resolve_parent_names(processes):
    """Fill parent_name from the scanned processes.

    Windows reuses PIDs. When the original parent has exited, its PID may
    now belong to an unrelated, newer process. A "parent" that started
    after the child is therefore treated as unknown rather than trusted.
    """
    by_pid = {
        item["pid"]: item
        for item in processes
        if item.get("pid") is not None
    }

    for item in processes:
        parent_pid = item.get("parent_pid")
        if parent_pid is None:
            continue

        parent = by_pid.get(parent_pid)
        if parent is None or parent is item:
            item["metadata_notes"].append(
                "Parent process is no longer running or is not visible"
            )
            continue

        child_started = item.get("create_time")
        parent_started = parent.get("create_time")

        if (
            child_started is not None
            and parent_started is not None
            and parent_started > child_started
        ):
            item["metadata_notes"].append(
                "Original parent process has exited (its PID was reused)"
            )
            continue

        if parent.get("name") is None:
            item["metadata_notes"].append("Parent process name unavailable")
            continue

        item["parent_name"] = parent["name"]


def scan_processes(cpu_interval=0.25):
    """
    Collect running process metadata.

    CPU measurement uses two readings separated by a short interval.
    Missing information is recorded without assuming malicious activity.

    Args:
        cpu_interval: Seconds between CPU measurements.

    Returns:
        A list of dictionaries containing process metadata.
    """
    if cpu_interval < 0:
        raise ValueError("cpu_interval cannot be negative")

    process_objects = []

    # First pass: prime CPU measurements for existing processes.
    for process in psutil.process_iter():
        try:
            process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            # CPU is unavailable, but the remaining metadata may not be.
            pass

        process_objects.append(process)

    # One shared wait, rather than waiting separately for every process.
    if cpu_interval > 0:
        time.sleep(cpu_interval)

    # Second pass: collect metadata and CPU readings.
    processes = []

    for process in process_objects:
        process_info = _collect_process_info(process)

        if process_info is not None:
            processes.append(process_info)

    _resolve_parent_names(processes)

    return processes
