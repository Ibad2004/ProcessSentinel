
import pytest

from pc_security.core.scan_service import ProcessScanService


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
