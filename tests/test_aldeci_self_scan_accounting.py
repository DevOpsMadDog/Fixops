from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "aldeci_self_scan.py"
SPEC = importlib.util.spec_from_file_location("aldeci_self_scan", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
aldeci_self_scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(aldeci_self_scan)


def reset_counters() -> None:
    aldeci_self_scan.PASS = 0
    aldeci_self_scan.FAIL = 0
    aldeci_self_scan.TOTAL = 0
    aldeci_self_scan.CURRENT_STEP_STATUS = None
    aldeci_self_scan.STEP_OPEN = False


def test_multiple_ok_messages_count_as_one_passed_step() -> None:
    reset_counters()

    aldeci_self_scan.step("multi-ok step")
    aldeci_self_scan.ok("first success message")
    aldeci_self_scan.ok("second success message")
    aldeci_self_scan._finalize_step()

    assert aldeci_self_scan.TOTAL == 1
    assert aldeci_self_scan.PASS == 1
    assert aldeci_self_scan.FAIL == 0


def test_fail_overrides_prior_ok_within_same_step() -> None:
    reset_counters()

    aldeci_self_scan.step("mixed outcome step")
    aldeci_self_scan.ok("partial success")
    aldeci_self_scan.fail("final failure")
    aldeci_self_scan._finalize_step()

    assert aldeci_self_scan.TOTAL == 1
    assert aldeci_self_scan.PASS == 0
    assert aldeci_self_scan.FAIL == 1


def test_starting_new_step_finalizes_previous_step() -> None:
    reset_counters()

    aldeci_self_scan.step("first step")
    aldeci_self_scan.ok("completed")
    aldeci_self_scan.step("second step")
    aldeci_self_scan.ok("completed")
    aldeci_self_scan._finalize_step()

    assert aldeci_self_scan.TOTAL == 2
    assert aldeci_self_scan.PASS == 2
    assert aldeci_self_scan.FAIL == 0


def test_warn_only_step_does_not_create_false_pass_or_fail() -> None:
    reset_counters()

    aldeci_self_scan.step("warn-only step")
    aldeci_self_scan.warn("non-fatal warning")
    aldeci_self_scan._finalize_step()

    assert aldeci_self_scan.TOTAL == 1
    assert aldeci_self_scan.PASS == 0
    assert aldeci_self_scan.FAIL == 0
