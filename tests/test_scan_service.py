
import pytest

from pc_security.core.scan_service import ProcessScanService
from pc_security.scanner import file_inspector, network_scanner


@pytest.fixture(autouse=True)
def no_real_system_access(monkeypatch):
    """Tests using the default pipeline must never touch the real system."""
    monkeypatch.setattr(
        network_scanner.psutil, "net_connections", lambda kind="inet": []
    )

    def no_powershell(*args, **kwargs):
        raise AssertionError("tests must not start PowerShell")

    monkeypatch.setattr(file_inspector, "_run_powershell", no_powershell)


def sample_process(pid, name):
    return {
        "pid": pid,
        "name": name,
        "exe_path": None,
        "cpu_percent": 0.0,
        "memory_mb": 10.0,
        "parent_pid": 1,
        "metadata_notes": [],
    }


def sample_analysis(process, risk_score=0):
    return {
        "pid": process["pid"],
        "name": process["name"],
        "exe_path": process["exe_path"],
        "risk_score": risk_score,
        "risk_level": "medium" if risk_score else "low",
        "findings": [],
    }


class FakeExplanationService:
    def __init__(self):
        self.called_pids = []

    def explain_process(self, analysis):
        self.called_pids.append(analysis["pid"])
        return {
            "pid": analysis["pid"],
            "explanation": "Simulated explanation.",
        }


def test_scan_runs_scanner_and_analyzer():
    processes = [sample_process(101, "example.exe")]
    scanner_calls = []

    def fake_scanner():
        scanner_calls.append(True)
        return processes

    def fake_analyzer(items):
        assert items == processes
        return [sample_analysis(items[0])]

    service = ProcessScanService(
        scanner=fake_scanner,
        analyzer=fake_analyzer,
    )

    result = service.run_scan()

    assert scanner_calls == [True]
    assert result["scanned_count"] == 1
    assert len(result["analyses"]) == 1
    assert result["ai_explanations"] == []


def test_ai_is_not_called_when_disabled():
    processes = [sample_process(101, "example.exe")]
    fake_ai = FakeExplanationService()

    service = ProcessScanService(
        scanner=lambda: processes,
        analyzer=lambda items: [sample_analysis(items[0], 35)],
        explanation_service=fake_ai,
    )

    result = service.run_scan(include_ai=False)

    assert fake_ai.called_pids == []
    assert result["ai_enabled_for_scan"] is False


def test_ai_explains_only_positive_risk_scores():
    processes = [
        sample_process(101, "normal.exe"),
        sample_process(102, "review.exe"),
    ]
    fake_ai = FakeExplanationService()

    service = ProcessScanService(
        scanner=lambda: processes,
        analyzer=lambda items: [
            sample_analysis(items[0], 0),
            sample_analysis(items[1], 35),
        ],
        explanation_service=fake_ai,
    )

    result = service.run_scan(include_ai=True)

    assert fake_ai.called_pids == [102]
    assert len(result["ai_explanations"]) == 1


def test_ai_request_limit_is_respected():
    processes = [
        sample_process(pid, f"process{pid}.exe")
        for pid in range(1, 5)
    ]
    fake_ai = FakeExplanationService()

    service = ProcessScanService(
        scanner=lambda: processes,
        analyzer=lambda items: [
            sample_analysis(item, 25) for item in items
        ],
        explanation_service=fake_ai,
        max_ai_explanations=2,
    )

    result = service.run_scan(include_ai=True)

    assert len(result["ai_explanations"]) == 2
    assert fake_ai.called_pids == [1, 2]
    assert result["ai_skipped_count"] == 2


def test_ai_failure_does_not_discard_scan_results():
    processes = [sample_process(101, "review.exe")]

    class FailingAI:
        def explain_process(self, analysis):
            raise RuntimeError("Simulated AI failure")

    service = ProcessScanService(
        scanner=lambda: processes,
        analyzer=lambda items: [sample_analysis(items[0], 35)],
        explanation_service=FailingAI(),
    )

    result = service.run_scan(include_ai=True)

    assert result["scanned_count"] == 1
    assert result["analyses"][0]["risk_score"] == 35
    assert result["ai_explanations"] == []
    assert len(result["ai_errors"]) == 1


def test_invalid_ai_limit_is_rejected():
    with pytest.raises(ValueError):
        ProcessScanService(max_ai_explanations=0)


def test_invalid_include_ai_value_is_rejected():
    service = ProcessScanService(
        scanner=lambda: [],
        analyzer=lambda items: [],
    )

    with pytest.raises(ValueError):
        service.run_scan(include_ai="yes")


def test_explanation_service_factory_is_used_for_ai_scan():
    processes = [sample_process(101, "review.exe")]
    created = []

    def factory():
        service = FakeExplanationService()
        created.append(service)
        return service

    service = ProcessScanService(
        scanner=lambda: processes,
        analyzer=lambda items: [sample_analysis(items[0], 35)],
        explanation_service_factory=factory,
    )

    service.run_scan(include_ai=True)

    assert len(created) == 1
    assert created[0].called_pids == [101]


def test_signatures_are_checked_after_scan_and_before_analysis():
    events = []
    processes = [sample_process(101, "example.exe")]

    def fake_scanner():
        events.append("scan")
        return processes

    def fake_inspector(items):
        events.append("inspect")
        assert items is processes
        for item in items:
            item["signature_status"] = "unsigned"

    def fake_analyzer(items):
        events.append("analyze")
        assert items[0]["signature_status"] == "unsigned"
        return [sample_analysis(items[0])]

    messages = []
    service = ProcessScanService(
        scanner=fake_scanner,
        analyzer=fake_analyzer,
        file_inspector=fake_inspector,
    )

    result = service.run_scan(progress_callback=messages.append)

    assert events == ["scan", "inspect", "analyze"]
    assert "Checking digital signatures..." in messages
    assert result["file_inspection_error"] is None


def test_signature_check_failure_does_not_stop_scan():
    def failing_inspector(items):
        raise RuntimeError("signature service unavailable")

    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "example.exe")],
        analyzer=lambda items: [sample_analysis(items[0])],
        file_inspector=failing_inspector,
    )

    result = service.run_scan()

    assert result["scanned_count"] == 1
    assert len(result["analyses"]) == 1
    assert "unavailable" in result["file_inspection_error"]


def test_default_pipeline_uses_inspect_processes():
    from pc_security.scanner.file_inspector import inspect_processes

    assert ProcessScanService().file_inspector is inspect_processes


def established(pid, remote_ip, remote_port=443):
    return {
        "pid": pid, "protocol": "TCP",
        "local_address": "10.0.0.2", "local_port": 50000,
        "remote_address": remote_ip, "remote_port": remote_port,
        "status": "ESTABLISHED",
    }


def test_network_step_runs_after_scan_and_feeds_analyzer():
    events = []
    processes = [sample_process(101, "example.exe")]

    def fake_scanner():
        events.append("scan")
        return processes

    def fake_network():
        events.append("network")
        return {
            "connections": [established(101, "1.1.1.1")],
            "notes": ["run as administrator to see more"],
        }

    def fake_analyzer(items):
        events.append("analyze")
        assert items[0]["outbound_connection_count"] == 1
        assert items[0]["remote_endpoints"] == ["1.1.1.1:443"]
        return [sample_analysis(items[0])]

    messages = []
    service = ProcessScanService(
        scanner=fake_scanner,
        analyzer=fake_analyzer,
        file_inspector=lambda items: events.append("inspect"),
        network_scanner=fake_network,
    )

    result = service.run_scan(progress_callback=messages.append)

    assert events == ["scan", "network", "inspect", "analyze"]
    assert "Checking network connections..." in messages
    assert result["network_error"] is None
    assert result["network_notes"] == ["run as administrator to see more"]
    assert result["network_connections"][0]["process_name"] == "example.exe"


def test_network_failure_does_not_stop_scan():
    def failing_network():
        raise RuntimeError("network listing denied")

    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "example.exe")],
        analyzer=lambda items: [sample_analysis(items[0])],
        file_inspector=lambda items: None,
        network_scanner=failing_network,
    )

    result = service.run_scan()

    assert result["scanned_count"] == 1
    assert "denied" in result["network_error"]
    assert result["network_connections"] == []
    assert result["network_notes"] == []


def test_default_pipeline_uses_network_scanner():
    from pc_security.scanner.network_scanner import collect_connections

    assert ProcessScanService().network_scanner is collect_connections


class FakeHistory:
    def __init__(self, new_pids=(), error=None):
        self.new_pids = set(new_pids)
        self.error = error
        self.recorded = []

    def record_scan(self, analyses, scanned_count=None):
        if self.error is not None:
            raise self.error
        for item in analyses:
            item["is_new_since_last_scan"] = item["pid"] in self.new_pids
        self.recorded.append((list(analyses), scanned_count))
        return 7


def test_history_is_saved_before_ai_and_marks_new():
    seen_by_ai = []

    class RecordingAI:
        def explain_process(self, analysis):
            seen_by_ai.append(analysis["is_new_since_last_scan"])
            return {"pid": analysis["pid"], "explanation": "ok"}

    history = FakeHistory(new_pids={102})
    messages = []
    service = ProcessScanService(
        scanner=lambda: [
            sample_process(101, "old.exe"), sample_process(102, "new.exe"),
        ],
        analyzer=lambda items: [sample_analysis(i, 35) for i in items],
        explanation_service=RecordingAI(),
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
        history=history,
    )

    result = service.run_scan(include_ai=True, progress_callback=messages.append)

    assert history.recorded[0][1] == 2
    assert result["history_scan_id"] == 7
    assert result["history_error"] is None
    assert {a["pid"]: a["is_new_since_last_scan"] for a in result["analyses"]} == {
        101: False, 102: True,
    }
    assert sorted(seen_by_ai) == [False, True]
    assert "Saving scan history..." in messages


def test_history_failure_does_not_stop_scan():
    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "example.exe")],
        analyzer=lambda items: [sample_analysis(items[0])],
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
        history=FakeHistory(error=RuntimeError("database is locked")),
    )

    result = service.run_scan()

    assert result["scanned_count"] == 1
    assert "locked" in result["history_error"]
    assert result["analyses"][0]["is_new_since_last_scan"] is False


def test_without_history_nothing_is_new():
    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "example.exe")],
        analyzer=lambda items: [sample_analysis(items[0])],
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
    )

    result = service.run_scan()

    assert result["history_scan_id"] is None
    assert result["history_error"] is None
    assert result["analyses"][0]["is_new_since_last_scan"] is False


def test_real_history_store_in_pipeline(tmp_path):
    from pc_security.core.history import ScanHistory

    history = ScanHistory(tmp_path / "data" / "history.db")
    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "example.exe")],
        analyzer=lambda items: [sample_analysis(items[0])],
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
        history=history,
    )

    service.run_scan()
    service.run_scan()

    assert len(history.list_scans()) == 2


def test_no_positive_scores_sends_nothing_to_ai():
    fake_ai = FakeExplanationService()
    messages = []
    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "a.exe"), sample_process(102, "b.exe")],
        analyzer=lambda items: [sample_analysis(item, 0) for item in items],
        explanation_service=fake_ai,
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
    )

    result = service.run_scan(include_ai=True, progress_callback=messages.append)

    assert fake_ai.called_pids == []
    assert result["ai_selection_mode"] == "no_indicators"
    assert result["ai_candidate_pids"] == []
    assert result["ai_explanations"] == []
    assert any("No indicators found" in m for m in messages)


def test_no_indicators_never_builds_an_ai_client():
    def factory():
        raise AssertionError("AI must not be contacted")

    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "a.exe")],
        analyzer=lambda items: [sample_analysis(items[0], 0)],
        explanation_service_factory=factory,
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
    )

    assert service.run_scan(include_ai=True)["ai_selection_mode"] == (
        "no_indicators"
    )


def test_positive_scores_use_positive_score_mode():
    service = ProcessScanService(
        scanner=lambda: [sample_process(101, "a.exe")],
        analyzer=lambda items: [sample_analysis(items[0], 10)],
        explanation_service=FakeExplanationService(),
        file_inspector=lambda items: None,
        network_scanner=lambda: {"connections": [], "notes": []},
    )

    result = service.run_scan(include_ai=True)

    assert result["ai_selection_mode"] == "positive_score"
    assert result["ai_candidate_pids"] == [101]


def test_contextual_review_code_is_gone():
    assert not hasattr(ProcessScanService, "_rank_contextual_candidates")
