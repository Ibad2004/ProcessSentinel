
from PySide6.QtWidgets import QApplication

from pc_security.ui.process_tree import ProcessTreeWidget, build_process_forest


_APP = QApplication.instance() or QApplication([])


def proc(pid, parent_pid, name=None, create_time=None, notes=(), **extra):
    item = {
        "pid": pid,
        "parent_pid": parent_pid,
        "name": name or f"p{pid}.exe",
        "create_time": create_time,
        "metadata_notes": list(notes),
        "risk_score": 0,
        "risk_level": "low",
    }
    item.update(extra)
    return item


def shape(forest):
    """Turn the forest into nested (pid, [children]) tuples."""
    return [
        (node["analysis"]["pid"], shape(node["children"]))
        for node in forest
    ]


def all_pids(forest):
    pids = []
    for node in forest:
        pids.append(node["analysis"]["pid"])
        pids.extend(all_pids(node["children"]))
    return pids


def test_children_are_nested_under_parents():
    forest = build_process_forest([
        proc(4, 0, "System"),
        proc(600, 4, "smss.exe"),
        proc(1000, 900, "explorer.exe"),  # parent 900 not visible
        proc(2000, 1000, "notepad.exe"),
        proc(2001, 1000, "cmd.exe"),
    ])

    assert shape(forest) == [
        (4, [(600, [])]),
        (1000, [(2000, []), (2001, [])]),
    ]


def test_missing_and_self_parents_become_roots():
    forest = build_process_forest([
        proc(0, 0, "System Idle Process"),
        proc(5, None),
        proc(6, 12345),
    ])

    assert shape(forest) == [(0, []), (5, []), (6, [])]


def test_reused_parent_pid_becomes_root():
    forest = build_process_forest([
        # PID 10 started after its "child", so it is not the real parent.
        proc(10, 1, create_time=500.0),
        proc(20, 10, create_time=100.0),
        # The scanner's note is also respected.
        proc(30, 10, create_time=600.0,
             notes=["Original parent process has exited (its PID was reused)"]),
        proc(40, 10, create_time=700.0),
    ])

    assert shape(forest) == [(10, [(40, [])]), (20, []), (30, [])]


def test_cycles_are_broken_and_every_process_appears_once():
    forest = build_process_forest([
        proc(1, 3),
        proc(2, 1),
        proc(3, 2),       # 1 -> 3 -> 2 -> 1
        proc(4, 4),       # self-parent
        proc(5, 2),       # hangs off the cycle
    ])

    pids = all_pids(forest)
    assert sorted(pids) == [1, 2, 3, 4, 5]
    assert len(pids) == len(set(pids))
    assert shape(forest)[0] == (1, [(2, [(3, []), (5, [])])])


def test_processes_without_pid_are_kept_as_roots():
    forest = build_process_forest([proc(None, 4), proc(4, 0)])

    assert [node["analysis"]["pid"] for node in forest] == [4, None]


def test_tree_widget_keeps_colours_signature_and_filters():
    tree = ProcessTreeWidget()
    tree.populate([
        proc(1, 0, "parent.exe", signature_status="unsigned",
             risk_score=35, risk_level="medium"),
        proc(2, 1, "child.exe", is_new_since_last_scan=True),
        proc(3, 1, "other.exe"),
    ])

    root = tree.topLevelItem(0)
    assert root.text(0) == "parent.exe"
    assert root.text(3) == "MEDIUM"
    assert root.text(4) == "Unsigned"
    assert root.childCount() == 2

    # Searching a child keeps its parent visible for context.
    assert tree.apply_filter("child") == 1
    assert not root.isHidden()
    assert not tree.item_for_pid(2).isHidden()
    assert tree.item_for_pid(3).isHidden()

    assert tree.apply_filter("", only_new=True) == 1
    assert tree.item_for_pid(3).isHidden()

    tree.apply_filter("")
    assert tree.select_pid(3)
    assert tree.selected_pid() == 3
    assert not tree.select_pid(999)
