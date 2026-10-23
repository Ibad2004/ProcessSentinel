
"""Read-only scanner for collecting Windows process information."""

import time

import psutil


def _normalize_text(value):
    """Convert empty strings and whitespace-only strings to None."""
    if isinstance(value, str):
        return value.strip() or None

    return value


def _collect_process_info(process):
    """Collect metadata for one process without modifying it."""
    try:
        info = process.as_dict(
            attrs=[
                "pid",
                "name",
                "exe",
                "memory_info",
                "ppid",
            ],
            ad_value=None,
        )
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None
    except psutil.AccessDenied:
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

    notes = []

    if name is None:
        notes.append("Process name unavailable")

    if exe_path is None:
        notes.append("Executable path unavailable")

    if memory_info is None:
        notes.append("Memory information unavailable")

    if info.get("ppid") is None:
        notes.append("Parent process ID unavailable")

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
        "metadata_notes": notes,
    }


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
            process_objects.append(process)
        except (
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            psutil.AccessDenied,
        ):
            continue

    # One shared wait, rather than waiting separately for every process.
    if cpu_interval > 0:
        time.sleep(cpu_interval)

    # Second pass: collect metadata and CPU readings.
    processes = []

    for process in process_objects:
        process_info = _collect_process_info(process)

        if process_info is not None:
            processes.append(process_info)

    return processes
