
"""Orchestrate read-only process scanning, analysis, and AI explanations."""

from pc_security.scanner.file_inspector import inspect_processes
from pc_security.scanner.network_scanner import (
    attach_network_info,
    collect_connections,
)
from pc_security.scanner.process_scanner import scan_processes
from pc_security.security.analyzer import analyze_processes


NO_INDICATORS_MESSAGE = (
    "No indicators found by the current rules. Select a process and click "
    "Explain to ask the AI about it."
)


class ProcessScanService:
    """Coordinate process scanning and evidence-based AI explanations."""

    def __init__(
        self,
        scanner=None,
        analyzer=None,
        explanation_service=None,
        max_ai_explanations=10,
        explanation_service_factory=None,
        file_inspector=None,
        network_scanner=None,
        history=None,
    ):
        if (
            isinstance(max_ai_explanations, bool)
            or not isinstance(max_ai_explanations, int)
            or max_ai_explanations < 1
        ):
            raise ValueError("max_ai_explanations must be a positive integer")

        self.scanner = scanner or scan_processes
        self.analyzer = analyzer or analyze_processes
        self.file_inspector = file_inspector or inspect_processes
        self.network_scanner = network_scanner or collect_connections
        # Optional ScanHistory; None disables saving (and "new" marking).
        self.history = history
        self.explanation_service = explanation_service
        self.explanation_service_factory = explanation_service_factory
        self.max_ai_explanations = max_ai_explanations

    def _get_explanation_service(self):
        """Return the injected service, or build one from configuration."""
        if self.explanation_service is not None:
            return self.explanation_service

        if self.explanation_service_factory is not None:
            return self.explanation_service_factory()

        from pc_security.ai.explanation_service import AIExplanationService

        return AIExplanationService()

    @staticmethod
    def _pid_sort_key(analysis):
        pid = analysis.get("pid")
        return pid if isinstance(pid, int) else float("inf")

    @classmethod
    def _rank_candidates(cls, analyses):
        """Return positive-score candidates, highest score first."""
        candidates = [
            item
            for item in analyses
            if isinstance(item, dict)
            and isinstance(item.get("risk_score"), (int, float))
            and not isinstance(item.get("risk_score"), bool)
            and item["risk_score"] > 0
        ]

        return sorted(
            candidates,
            key=lambda item: (
                -item["risk_score"],
                cls._pid_sort_key(item),
            ),
        )

    def run_scan(self, include_ai=False, progress_callback=None):
        """Scan processes and optionally explain positive-score candidates.

        With include_ai, only processes that a rule scored above zero are
        sent to the AI (at most max_ai_explanations). If none were scored,
        nothing is sent and ai_selection_mode is "no_indicators".
        """
        if not isinstance(include_ai, bool):
            raise ValueError("include_ai must be a boolean")

        if progress_callback is not None and not callable(progress_callback):
            raise ValueError("progress_callback must be callable or None")

        def report(message):
            if progress_callback is not None:
                progress_callback(message)

        report("Collecting running processes...")
        processes = self.scanner()

        report("Checking network connections...")
        network = {"connections": [], "notes": []}
        network_error = None
        try:
            network = self.network_scanner()
            attach_network_info(processes, network["connections"])
        except Exception as exc:
            # Same pattern as signatures: network data is extra evidence.
            network = {"connections": [], "notes": []}
            network_error = str(exc)

        report("Checking digital signatures...")
        file_inspection_error = None
        try:
            self.file_inspector(processes)
        except Exception as exc:
            # Signatures are extra evidence; their absence must not stop
            # the scan. Rules treat missing signature data as "unknown".
            file_inspection_error = str(exc)

        report("Applying rule-based security analysis...")
        analyses = self.analyzer(processes)

        history_error = None
        history_scan_id = None
        for analysis in analyses:
            analysis["is_new_since_last_scan"] = False

        if self.history is not None:
            report("Saving scan history...")
            try:
                history_scan_id = self.history.record_scan(
                    analyses, scanned_count=len(processes)
                )
            except Exception as exc:
                # History is a convenience; a locked or broken database
                # must never stop the scan.
                history_error = str(exc)
                for analysis in analyses:
                    analysis["is_new_since_last_scan"] = False

        result = {
            "scanned_count": len(processes),
            "analyses": analyses,
            "ai_enabled_for_scan": include_ai,
            "ai_explanations": [],
            "ai_errors": [],
            "ai_skipped_count": 0,
            "ai_candidate_count": 0,
            "ai_candidate_pids": [],
            "ai_selection_mode": "not_requested",
            "file_inspection_error": file_inspection_error,
            "network_connections": network.get("connections", []),
            "network_notes": network.get("notes", []),
            "network_error": network_error,
            "history_scan_id": history_scan_id,
            "history_error": history_error,
        }

        if not include_ai:
            report("Rule-based scan complete.")
            return result

        candidates = self._rank_candidates(analyses)

        if not candidates:
            # Nothing is sent to the AI automatically; the user can still
            # explain a selected process manually.
            result["ai_selection_mode"] = "no_indicators"
            report(NO_INDICATORS_MESSAGE)
            return result

        result["ai_selection_mode"] = "positive_score"
        selected = candidates[:self.max_ai_explanations]

        result["ai_candidate_count"] = len(candidates)
        result["ai_skipped_count"] = max(0, len(candidates) - len(selected))
        result["ai_candidate_pids"] = [
            item["pid"] for item in selected
        ]

        explanation_service = self._get_explanation_service()

        total = len(selected)
        report(f"Explaining the top {total} positive-score candidates.")

        for index, analysis in enumerate(selected, start=1):
            pid = analysis.get("pid")
            report(f"AI explanation {index} of {total}: PID {pid}...")

            try:
                explanation = explanation_service.explain_process(
                    analysis
                )
                result["ai_explanations"].append(explanation)
            except Exception as exc:
                result["ai_errors"].append({
                    "pid": pid,
                    "error": str(exc),
                })

        report(
            f"Review complete. Received {len(result['ai_explanations'])} "
            f"explanations; {len(result['ai_errors'])} requests failed."
        )
        return result
