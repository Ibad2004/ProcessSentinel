
"""Orchestrate process scanning, rule analysis, and optional AI explanations."""

from pc_security.scanner.process_scanner import scan_processes
from pc_security.security.analyzer import analyze_processes


class ProcessScanService:
    """Coordinate the read-only process security analysis workflow."""

    def __init__(
        self,
        scanner=None,
        analyzer=None,
        explanation_service=None,
        max_ai_explanations=10,
    ):
        if (
            isinstance(max_ai_explanations, bool)
            or not isinstance(max_ai_explanations, int)
            or max_ai_explanations < 1
        ):
            raise ValueError("max_ai_explanations must be a positive integer")

        self.scanner = scanner or scan_processes
        self.analyzer = analyzer or analyze_processes
        self.explanation_service = explanation_service
        self.max_ai_explanations = max_ai_explanations

    def run_scan(self, include_ai=False):
        """
        Scan and analyze processes, optionally requesting AI explanations.

        AI explanations are requested only for processes with a positive
        rule-based risk score, up to the configured maximum.

        AI failures do not discard the underlying scan or rule findings.
        """
        if not isinstance(include_ai, bool):
            raise ValueError("include_ai must be a boolean")

        processes = self.scanner()
        analyses = self.analyzer(processes)

        result = {
            "scanned_count": len(processes),
            "analyses": analyses,
            "ai_enabled_for_scan": include_ai,
            "ai_explanations": [],
            "ai_errors": [],
            "ai_skipped_count": 0,
        }

        if not include_ai:
            return result

        if self.explanation_service is None:
            from pc_security.ai.explanation_service import AIExplanationService

            self.explanation_service = AIExplanationService()

        candidates = [
            analysis
            for analysis in analyses
            if analysis.get("risk_score", 0) > 0
        ]

        selected = candidates[:self.max_ai_explanations]
        result["ai_skipped_count"] = len(candidates) - len(selected)

        for analysis in selected:
            try:
                explanation = self.explanation_service.explain_process(analysis)
                result["ai_explanations"].append(explanation)
            except Exception as exc:
                # Preserve scan results if the optional AI service fails.
                result["ai_errors"].append({
                    "pid": analysis.get("pid"),
                    "error": str(exc),
                })

        return result
