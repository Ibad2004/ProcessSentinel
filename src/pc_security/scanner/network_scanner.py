
"""Read-only collection of network connections per process.

Connections are only listed, never opened, closed, or blocked.
"""

import socket

import psutil


MAX_REMOTE_ENDPOINTS = 20

ADMIN_NOTE = (
    "Some connections could not be read. Running ProcessSentinel as "
    "administrator shows more."
)

_PROTOCOLS = {
    socket.SOCK_STREAM: "TCP",
    socket.SOCK_DGRAM: "UDP",
}


def _split_address(address):
    """Return (ip, port) from a psutil address, or (None, None)."""
    if not address:
        return None, None

    try:
        return address[0] or None, address[1]
    except (IndexError, TypeError):
        return None, None


def format_endpoint(ip, port):
    """Format ip:port, bracketing IPv6 addresses ([::1]:443)."""
    if not ip:
        return None
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{port}" if port is not None else host


def _to_record(connection, pid=None):
    """Convert a psutil connection tuple into a plain dictionary."""
    local_ip, local_port = _split_address(getattr(connection, "laddr", None))
    remote_ip, remote_port = _split_address(
        getattr(connection, "raddr", None)
    )
    status = getattr(connection, "status", None)

    # psutil reports "NONE" for connectionless UDP sockets.
    if not status or status == psutil.CONN_NONE:
        status = None

    owner = getattr(connection, "pid", None)

    return {
        "pid": owner if owner is not None else pid,
        "protocol": _PROTOCOLS.get(getattr(connection, "type", None), "?"),
        "local_address": local_ip,
        "local_port": local_port,
        "remote_address": remote_ip,
        "remote_port": remote_port,
        "status": status,
    }


def _per_process_connections(notes):
    """Fallback when the system-wide call is denied: ask each process."""
    records = []
    denied = 0

    for process in psutil.process_iter():
        try:
            reader = getattr(process, "net_connections", None)
            if reader is None:  # psutil < 6
                reader = process.connections
            connections = reader(kind="inet")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            denied += 1
            continue

        records.extend(_to_record(item, pid=process.pid) for item in connections)

    if denied:
        notes.append(
            f"Network connections were hidden for {denied} processes. "
            + ADMIN_NOTE
        )

    return records


def collect_connections():
    """Return {"connections": [...], "notes": [...]} for all processes.

    Each connection: pid, protocol (TCP/UDP), local_address, local_port,
    remote_address, remote_port, status (ESTABLISHED, LISTEN, ... or None).
    """
    notes = []

    try:
        connections = [
            _to_record(item)
            for item in psutil.net_connections(kind="inet")
        ]
    except psutil.AccessDenied:
        notes.append(
            "The system-wide connection list was denied; reading each "
            "process separately instead."
        )
        connections = _per_process_connections(notes)

    return {"connections": connections, "notes": notes}


def is_outbound(connection):
    """An established connection that has a remote address."""
    return (
        connection.get("status") == psutil.CONN_ESTABLISHED
        and bool(connection.get("remote_address"))
    )


def attach_network_info(processes, connections):
    """Add per-process network fields in place and label each connection.

    Adds to each process: outbound_connection_count, remote_endpoints
    (unique, at most MAX_REMOTE_ENDPOINTS), listening_ports (sorted).
    Adds process_name to each connection.
    """
    by_pid = {
        item["pid"]: item
        for item in processes
        if item.get("pid") is not None
    }

    for item in processes:
        item["outbound_connection_count"] = 0
        item["remote_endpoints"] = []
        item["listening_ports"] = []

    for connection in connections:
        process = by_pid.get(connection.get("pid"))
        connection["process_name"] = process.get("name") if process else None

        if process is None:
            continue

        if is_outbound(connection):
            process["outbound_connection_count"] += 1
            endpoint = format_endpoint(
                connection["remote_address"], connection.get("remote_port")
            )
            if (
                endpoint not in process["remote_endpoints"]
                and len(process["remote_endpoints"]) < MAX_REMOTE_ENDPOINTS
            ):
                process["remote_endpoints"].append(endpoint)

        port = connection.get("local_port")
        if (
            connection.get("status") == psutil.CONN_LISTEN
            and port is not None
            and port not in process["listening_ports"]
        ):
            process["listening_ports"].append(port)

    for item in processes:
        item["listening_ports"].sort()

    return processes
