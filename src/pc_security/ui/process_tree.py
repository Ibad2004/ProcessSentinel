"""Parent/child process tree view."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTreeWidget, QTreeWidgetItem

from pc_security.ui.common import (
    NEW_ROW_BRUSH,
    NEW_TOOLTIP,
    risk_level_color,
    signature_color,
    signature_label,
)


NEW_ROLE = Qt.ItemDataRole.UserRole + 1

TREE_HEADERS = [
    "PROCESS", "PID", "RISK SCORE", "RISK LEVEL", "SIGNATURE", "EXECUTABLE",
]


def _has_valid_parent(analysis, parent):
    """True when parent really is this process's (still running) parent."""
    if parent is None or parent is analysis:
        return False

    notes = " ".join(analysis.get("metadata_notes") or []).lower()
    if "reused" in notes:
        return False

    # Windows reuses PIDs: a "parent" that started after the child is a
    # different, newer process.
    child_started = analysis.get("create_time")
    parent_started = parent.get("create_time")
    if (
        isinstance(child_started, (int, float))
        and isinstance(parent_started, (int, float))
        and parent_started > child_started
    ):
        return False

    return True


def build_process_forest(analyses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return root nodes {"analysis", "children"} built from parent_pid.

    Processes with a missing, invisible or reused-PID parent become roots.
    Cycles (possible with PID reuse) are broken by promoting the lowest PID
    in the cycle to a root, so every process appears exactly once.
    """
    by_pid = {}
    without_pid = []
    for analysis in analyses:
        pid = analysis.get("pid")
        if isinstance(pid, int) and pid not in by_pid:
            by_pid[pid] = analysis
        else:
            without_pid.append(analysis)

    parent_of = {}
    for pid, analysis in by_pid.items():
        parent_pid = analysis.get("parent_pid")
        parent = by_pid.get(parent_pid) if parent_pid != pid else None
        parent_of[pid] = (
            parent_pid if _has_valid_parent(analysis, parent) else None
        )

    while True:
        children: dict[int, list[int]] = {}
        for pid, parent_pid in parent_of.items():
            if parent_pid is not None:
                children.setdefault(parent_pid, []).append(pid)

        roots = sorted(pid for pid, parent in parent_of.items() if parent is None)
        reached = set()
        stack = list(roots)
        while stack:
            pid = stack.pop()
            if pid in reached:
                continue
            reached.add(pid)
            stack.extend(children.get(pid, []))

        unreached = set(parent_of) - reached
        if not unreached:
            break
        parent_of[min(unreached)] = None  # Break one cycle and retry.

    def make_node(pid):
        return {
            "analysis": by_pid[pid],
            "children": [make_node(child) for child in sorted(children.get(pid, []))],
        }

    forest = [make_node(pid) for pid in roots]
    forest.extend({"analysis": item, "children": []} for item in without_pid)
    return forest


class _TreeItem(QTreeWidgetItem):
    """Sort PID and score columns numerically."""

    NUMERIC_COLUMNS = {1, 2}

    def __lt__(self, other):
        column = self.treeWidget().sortColumn() if self.treeWidget() else 0
        if column in self.NUMERIC_COLUMNS:
            try:
                return float(self.text(column)) < float(other.text(column))
            except ValueError:
                pass
        return super().__lt__(other)


class ProcessTreeWidget(QTreeWidget):
    """Show processes under their parents, with the table's colours."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("processTree")
        self.setColumnCount(len(TREE_HEADERS))
        self.setHeaderLabels(TREE_HEADERS)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setSortingEnabled(False)

        header = self.header()
        for column in range(len(TREE_HEADERS) - 1):
            header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )
        header.setSectionResizeMode(
            len(TREE_HEADERS) - 1, QHeaderView.ResizeMode.Stretch
        )

        self._items_by_pid: dict[int, QTreeWidgetItem] = {}

    def populate(self, analyses: list[dict[str, Any]]) -> None:
        self.clear()
        self._items_by_pid = {}

        def add(node, parent_item):
            item = self._make_item(node["analysis"])
            if parent_item is None:
                self.addTopLevelItem(item)
            else:
                parent_item.addChild(item)
            for child in node["children"]:
                add(child, item)

        for root in build_process_forest(analyses):
            add(root, None)

        self.expandAll()

    def _make_item(self, analysis):
        level = str(analysis.get("risk_level", "low")).upper()
        signature_status = analysis.get("signature_status")
        item = _TreeItem([
            str(analysis.get("name") or "Unknown"),
            str(analysis.get("pid", "")),
            str(analysis.get("risk_score", 0) or 0),
            level,
            signature_label(signature_status),
            str(analysis.get("exe_path") or "Unavailable"),
        ])
        item.setForeground(3, risk_level_color(level))
        color = signature_color(signature_status)
        if color is not None:
            item.setForeground(4, color)

        pid = analysis.get("pid")
        item.setData(0, Qt.ItemDataRole.UserRole, pid)
        if isinstance(pid, int):
            self._items_by_pid[pid] = item

        is_new = bool(analysis.get("is_new_since_last_scan"))
        item.setData(0, NEW_ROLE, is_new)
        if is_new:
            font = QFont(item.font(0))
            font.setBold(True)
            item.setFont(0, font)
            for column in range(len(TREE_HEADERS)):
                item.setBackground(column, NEW_ROW_BRUSH)
                item.setToolTip(column, NEW_TOOLTIP)
        return item

    def apply_filter(self, query: str, only_new: bool = False) -> int:
        """Hide non-matching items; keep ancestors of matches visible.

        Returns the number of processes that match.
        """
        query = query.strip().casefold()
        matches = 0

        def visit(item):
            nonlocal matches
            text = " ".join(
                item.text(column) for column in range(self.columnCount())
            ).casefold()
            own_match = (not query or query in text) and (
                not only_new or bool(item.data(0, NEW_ROLE))
            )
            if own_match:
                matches += 1

            child_visible = False
            for index in range(item.childCount()):
                child_visible = visit(item.child(index)) or child_visible

            visible = own_match or child_visible
            item.setHidden(not visible)
            return visible

        for index in range(self.topLevelItemCount()):
            visit(self.topLevelItem(index))
        return matches

    def selected_pid(self) -> int | None:
        item = self.currentItem()
        if item is None or item.isHidden():
            return None
        pid = item.data(0, Qt.ItemDataRole.UserRole)
        return pid if isinstance(pid, int) else None

    def select_pid(self, pid: int) -> bool:
        item = self._items_by_pid.get(pid)
        if item is None:
            return False
        self.setCurrentItem(item)
        self.scrollToItem(item)
        return True

    def item_for_pid(self, pid: int):
        return self._items_by_pid.get(pid)
