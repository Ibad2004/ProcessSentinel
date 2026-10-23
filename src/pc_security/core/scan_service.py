
"""Orchestrate read-only process scanning, analysis, and AI explanations."""

from pc_security.scanner.process_scanner import scan_processes
from pc_security.security.analyzer import analyze_processes


class ProcessScanService:
    """Coordinate process scanning and evidence-based AI explanations."""

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

    @classmethod
    def _rank_contextual_candidates(cls, analyses):
        """Choose review candidates when no positive scores exist.

        This is a review prioritization, not a malware ranking. Processes
        with missing metadata are prioritized for review because less is
        known about them, not because missing data proves danger.
        """
        valid_analyses = [
            item for item in analyses
            if isinstance(item, dict) and item.get("pid") is not None
        ]

        def review_key(item):
            score = item.get("risk_score", 0)
            score = (
                score
                if isinstance(score, (int, float))
                and not isinstance(score, bool)
                else 0
            )

            path = item.get("exe_path")
            name = item.get("name")

            # Prioritize processes with less available evidence for review.
            missing_metadata = int(not name) + int(not path)

            return (
                -missing_metadata,
                -score,
                cls._pid_sort_key(item),
            )

        return sorted(valid_analyses, key=review_key)

    def run_scan(self, include_ai=False, progress_callback=None):
        """Scan processes and optionally explain up to 10 candidates."""
        if not isinstance(include_ai, bool):
            raise ValueError("include_ai must be a boolean")

        if progress_callback is not None and not callable(progress_callback):
            raise ValueError("progress_callback must be callable or None")

        def report(message):
            if progress_callback is not None:
                progress_callback(message)

        report("Collecting running processes...")
        processes = self.scanner()

        report("Applying rule-based security analysis...")
        analyses = self.analyzer(processes)

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
        }

        if not include_ai:
            report("Rule-based scan complete.")
            return result

        positive_candidates = self._rank_candidates(analyses)

        if positive_candidates:
            candidates = positive_candidates
            result["ai_selection_mode"] = "positive_score"
        else:
            # Do not silently skip AI when all rule scores are zero.
            # Explain that these are contextual review candidates.
            candidates = self._rank_contextual_candidates(analyses)
            result["ai_selection_mode"] = "contextual_review"

        selected = candidates[:self.max_ai_explanations]

        result["ai_candidate_count"] = len(candidates)
        result["ai_skipped_count"] = max(0, len(candidates) - len(selected))
        result["ai_candidate_pids"] = [
            item["pid"] for item in selected
        ]

        if not selected:
            report("Scan complete. No processes were available for review.")
            return result

        if self.explanation_service is None:
            from pc_security.ai.explanation_service import AIExplanationService

            self.explanation_service = AIExplanationService()

        total = len(selected)

        if result["ai_selection_mode"] == "positive_score":
            report(
                f"Explaining the top {total} positive-score candidates."
            )
        else:
            report(
                f"No positive-score candidates. Reviewing {total} "
                "processes contextually; this is not a suspiciousness ranking."
            )

        for index, analysis in enumerate(selected, start=1):
            pid = analysis.get("pid")
            report(f"AI explanation {index} of {total}: PID {pid}...")

            try:
                explanation = self.explanation_service.explain_process(
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
