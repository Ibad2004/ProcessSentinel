
import socket
from collections import namedtuple

import psutil
import pytest

import pc_security.scanner.network_scanner as ns


Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "fd family type laddr raddr status pid")
ProcConn = namedtuple("ProcConn", "fd family type laddr raddr status")


def tcp(pid, local, remote=(), status=psutil.CONN_ESTABLISHED):
    return Conn(
        -1, socket.AF_INET, socket.SOCK_STREAM,
        Addr(*local), Addr(*remote) if remote else (), status, pid,
    )


def udp(pid, local):
    return Conn(
        -1, socket.AF_INET, socket.SOCK_DGRAM,
        Addr(*local), (), psutil.CONN_NONE, pid,
    )


class FakeProcess:
    def __init__(self, pid, connections=(), error=None):
        self.pid = pid
        self.connections_list = list(connections)
        self.error = error
        self.kinds = []

    def net_connections(self, kind="inet"):
        self.kinds.append(kind)
        if self.error is not None:
            raise self.error
        return self.connections_list


@pytest.fixture
def fake_psutil(monkeypatch):
    state = {"system": [], "system_error": None, "processes": []}

    def net_connections(kind="inet"):
        assert kind == "inet"
        if state["system_error"] is not None:
            raise state["system_error"]
        return state["system"]

    monkeypatch.setattr(ns.psutil, "net_connections", net_connections)
    monkeypatch.setattr(
        ns.psutil, "process_iter", lambda: list(state["processes"])
    )
    return state


def test_collects_tcp_connection_fields(fake_psutil):
    fake_psutil["system"] = [
        tcp(10, ("192.168.1.5", 50000), ("93.184.216.34", 443)),
    ]

    result = ns.collect_connections()

    assert result["notes"] == []
    assert result["connections"] == [{
        "pid": 10,
        "protocol": "TCP",
        "local_address": "192.168.1.5",
        "local_port": 50000,
        "remote_address": "93.184.216.34",
        "remote_port": 443,
        "status": "ESTABLISHED",
    }]


def test_udp_without_remote_address(fake_psutil):
    fake_psutil["system"] = [udp(20, ("0.0.0.0", 5353))]

    connection = ns.collect_connections()["connections"][0]

    assert connection["protocol"] == "UDP"
    assert connection["remote_address"] is None
    assert connection["remote_port"] is None
    assert connection["status"] is None


def test_empty_results(fake_psutil):
    assert ns.collect_connections() == {"connections": [], "notes": []}


def test_access_denied_falls_back_to_each_process(fake_psutil):
    fake_psutil["system_error"] = psutil.AccessDenied()
    allowed = FakeProcess(
        30,
        [ProcConn(-1, socket.AF_INET, socket.SOCK_STREAM,
                  Addr("10.0.0.2", 4000), Addr("1.1.1.1", 443),
                  psutil.CONN_ESTABLISHED)],
    )
    denied = FakeProcess(4, error=psutil.AccessDenied(4))
    vanished = FakeProcess(99, error=psutil.NoSuchProcess(99))
    fake_psutil["processes"] = [allowed, denied, vanished]

    result = ns.collect_connections()

    assert [c["pid"] for c in result["connections"]] == [30]
    assert allowed.kinds == ["inet"]
    assert any("each process" in note for note in result["notes"])
    assert any(
        "1 processes" in note and "administrator" in note
        for note in result["notes"]
    )


def test_attach_network_info_counts_and_caps(monkeypatch):
    monkeypatch.setattr(ns, "MAX_REMOTE_ENDPOINTS", 2)
    processes = [
        {"pid": 1, "name": "browser.exe"},
        {"pid": 2, "name": "server.exe"},
    ]
    connections = [
        ns._to_record(tcp(1, ("10.0.0.2", 1), ("1.1.1.1", 443))),
        ns._to_record(tcp(1, ("10.0.0.2", 2), ("1.1.1.1", 443))),
        ns._to_record(tcp(1, ("10.0.0.2", 3), ("8.8.8.8", 443))),
        ns._to_record(tcp(1, ("10.0.0.2", 4), ("9.9.9.9", 443))),
        ns._to_record(tcp(1, ("10.0.0.2", 5), ("2.2.2.2", 80),
                          status=psutil.CONN_TIME_WAIT)),
        ns._to_record(tcp(2, ("0.0.0.0", 8080), status=psutil.CONN_LISTEN)),
        ns._to_record(tcp(2, ("::", 443), status=psutil.CONN_LISTEN)),
        ns._to_record(tcp(2, ("0.0.0.0", 8080), status=psutil.CONN_LISTEN)),
        ns._to_record(udp(2, ("0.0.0.0", 53))),
        ns._to_record(tcp(77, ("10.0.0.2", 9), ("3.3.3.3", 443))),
    ]

    ns.attach_network_info(processes, connections)
    browser, server = processes

    assert browser["outbound_connection_count"] == 4
    assert browser["remote_endpoints"] == ["1.1.1.1:443", "8.8.8.8:443"]
    assert browser["listening_ports"] == []
    assert server["outbound_connection_count"] == 0
    assert server["listening_ports"] == [443, 8080]
    assert connections[0]["process_name"] == "browser.exe"
    assert connections[-1]["process_name"] is None


def test_processes_without_connections_get_zero_values():
    processes = [{"pid": 5, "name": "idle.exe"}]

    ns.attach_network_info(processes, [])

    assert processes[0]["outbound_connection_count"] == 0
    assert processes[0]["remote_endpoints"] == []
    assert processes[0]["listening_ports"] == []


def test_ipv6_endpoints_are_bracketed():
    assert ns.format_endpoint("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert ns.format_endpoint("1.2.3.4", 80) == "1.2.3.4:80"
    assert ns.format_endpoint(None, 80) is None
