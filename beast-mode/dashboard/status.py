#!/usr/bin/env python3
"""Beast Mode Status Dashboard — Real-time progress visualization.

Displays current execution state with progress bars, task status,
and performance metrics using ANSI colors and simple formatting.
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional


class StatusDashboard:
    """Displays real-time status of Beast Mode execution."""

    # ANSI color codes
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self, state_file: Path):
        self.state_file = state_file

    def _load_state(self) -> Dict[str, Any]:
        """Load current state from JSON file."""
        if not self.state_file.exists():
            return {"status": "IDLE", "current_phase": 1, "phases": {}}

        with open(self.state_file) as f:
            return json.load(f)

    def _get_progress_bar(
        self,
        current: int,
        total: int,
        width: int = 20,
    ) -> str:
        """Create a progress bar string."""
        if total == 0:
            return "▓" * width

        filled = int((current / total) * width)
        bar = "▓" * filled + "░" * (width - filled)
        percentage = int((current / total) * 100)
        return f"{bar} {percentage}%"

    def _format_time_duration(self, seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"

    def _format_timestamp(self, timestamp: str) -> str:
        """Format ISO timestamp to human-readable."""
        if not timestamp:
            return "N/A"
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return timestamp[:19]

    def _get_status_icon(self, status: str) -> str:
        """Get icon for status."""
        icons = {
            "PASSED": f"{self.GREEN}✓{self.RESET}",
            "FAILED": f"{self.RED}✗{self.RESET}",
            "RUNNING": f"{self.BLUE}→{self.RESET}",
            "PENDING": "•",
            "BLOCKED": f"{self.RED}⊘{self.RESET}",
            "SKIPPED": "⊘",
        }
        return icons.get(status, "?")

    def _get_status_color(self, status: str) -> str:
        """Get color for status."""
        if status == "PASSED":
            return self.GREEN
        elif status in ["FAILED", "BLOCKED"]:
            return self.RED
        elif status == "RUNNING":
            return self.BLUE
        elif status == "PENDING":
            return self.YELLOW
        else:
            return self.RESET

    def print_dashboard(self, phase_id: Optional[int] = None):
        """Print real-time status dashboard."""
        state = self._load_state()

        print(f"\n{self.BOLD}{'='*70}")
        print("Beast Mode Status Dashboard")
        print(f"{'='*70}{self.RESET}\n")

        # Overall status
        status = state.get("status", "IDLE")
        status_color = self._get_status_color(status)
        print(f"Status: {status_color}{status}{self.RESET}")
        print(f"Current Phase: {state.get('current_phase')}/10")

        # Timing information
        start_time = state.get("start_time")
        if start_time:
            start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            elapsed = datetime.utcnow() - start_dt.replace(tzinfo=None)
            print(f"Started: {self._format_timestamp(start_time)}")
            print(f"Elapsed: {self._format_time_duration(elapsed.total_seconds())}")

        # Phase overview
        print(f"\n{self.BOLD}Phases:{self.RESET}")
        phases = state.get("phases", {})

        if not phases:
            print("  No phases executed yet")
        else:
            phase_list = sorted(phases.keys(), key=int)

            for phase_key in phase_list:
                if phase_id and int(phase_key) != phase_id:
                    continue

                phase_data = phases[phase_key]
                phase_num = int(phase_key)
                phase_name = phase_data.get("name", f"Phase {phase_num}")
                phase_status = phase_data.get("status", "UNKNOWN")

                status_icon = self._get_status_icon(phase_status)
                status_color = self._get_status_color(phase_status)

                # Phase header
                print(f"\n  {status_icon} Phase {phase_num}: {phase_name}")
                print(f"     Status: {status_color}{phase_status}{self.RESET}")

                # Phase details
                duration = phase_data.get("duration_seconds", 0)
                print(f"     Duration: {self._format_time_duration(duration)}")

                # Tasks
                tasks = phase_data.get("tasks", [])
                if tasks:
                    print(f"     Tasks: {len(tasks)}")
                    passed = sum(1 for t in tasks if t.get("status") == "PASSED")
                    failed = sum(1 for t in tasks if t.get("status") == "FAILED")
                    running = sum(1 for t in tasks if t.get("status") == "RUNNING")

                    if phase_id:
                        # Detailed task view
                        print(f"       Passed: {self.GREEN}{passed}{self.RESET}")
                        print(f"       Failed: {self.RED}{failed}{self.RESET}")
                        print(f"       Running: {self.BLUE}{running}{self.RESET}")

                        print(f"\n       Task Details:")
                        for task in tasks:
                            task_status = task.get("status")
                            task_icon = self._get_status_icon(task_status)
                            task_duration = task.get("duration_seconds", 0)

                            print(
                                f"         {task_icon} {task.get('task_id')}: "
                                f"{task_status} ({self._format_time_duration(task_duration)})"
                            )

                            if task.get("error_message"):
                                print(
                                    f"            Error: {task.get('error_message')[:80]}"
                                )
                    else:
                        # Summary view
                        summary = f"{self.GREEN}{passed}✓{self.RESET} "
                        if failed > 0:
                            summary += f"{self.RED}{failed}✗{self.RESET} "
                        if running > 0:
                            summary += f"{self.BLUE}{running}→{self.RESET}"

                        print(f"       {summary}")

                    # Progress bar
                    if tasks:
                        progress_bar = self._get_progress_bar(passed, len(tasks))
                        print(f"       Progress: {progress_bar}")

                # Gate results
                gate_result = phase_data.get("gate_result")
                if gate_result:
                    gate_status = gate_result.get("status")
                    gate_icon = self._get_status_icon(gate_status)
                    print(f"     {gate_icon} Gate: {gate_status}")

        # Summary statistics
        if phases:
            print(f"\n{self.BOLD}Summary:{self.RESET}")
            total_phases = len(phases)
            passed_phases = sum(1 for p in phases.values() if p.get("status") == "PASSED")
            failed_phases = sum(1 for p in phases.values() if p.get("status") == "FAILED")
            blocked_phases = sum(1 for p in phases.values() if p.get("status") == "BLOCKED")

            print(
                f"  Phases: {self.GREEN}{passed_phases} passed{self.RESET}, "
                f"{self.RED}{failed_phases} failed{self.RESET}, "
                f"{self.RED}{blocked_phases} blocked{self.RESET}"
            )

            # Total tasks
            total_tasks = 0
            passed_tasks = 0
            for phase in phases.values():
                tasks = phase.get("tasks", [])
                total_tasks += len(tasks)
                passed_tasks += sum(1 for t in tasks if t.get("status") == "PASSED")

            if total_tasks > 0:
                print(f"  Tasks: {self.GREEN}{passed_tasks}/{total_tasks}{self.RESET} passed")

        # Error summary
        errors = state.get("errors", [])
        if errors:
            print(f"\n{self.BOLD}Recent Errors:{self.RESET}")
            for error in errors[-5:]:
                print(f"  {self.RED}✗{self.RESET} {error[:70]}")

        print(f"\n{self.BOLD}{'='*70}{self.RESET}\n")

    def watch_status(self, interval: int = 10):
        """Watch status continuously with auto-refresh."""
        try:
            while True:
                # Clear screen
                print("\033[2J\033[H")  # ANSI clear screen
                self.print_dashboard()

                # Check if complete
                state = self._load_state()
                if state.get("status") in ["COMPLETED", "FAILED"]:
                    print(f"Beast Mode has {state.get('status')}. Exiting watch mode.")
                    break

                time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n{self.YELLOW}Stopped watching status{self.RESET}")


# ============================================================================
# CLI Interface
# ============================================================================

if __name__ == "__main__":
    import sys

    state_file = Path(__file__).parent / "logs" / "beast_state.json"

    dashboard = StatusDashboard(state_file)

    if len(sys.argv) > 1:
        if sys.argv[1] == "watch":
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            dashboard.watch_status(interval)
        elif sys.argv[1].isdigit():
            phase_id = int(sys.argv[1])
            dashboard.print_dashboard(phase_id)
        else:
            dashboard.print_dashboard()
    else:
        dashboard.print_dashboard()
