#!/usr/bin/env python3
"""Beast Mode v6 — Autonomous ALDECI Development Orchestrator

Orchestrates Claude Code agents to build ALDECI across 10 sequential phases
with parallel task execution, automated validation gates, and progress tracking.
"""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ============================================================================
# Configuration & Logging
# ============================================================================

def setup_logging(log_level: str) -> logging.Logger:
    """Configure logging to file and console."""
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / "beast.log"

    logger = logging.getLogger("BeastMode")
    logger.setLevel(getattr(logging, log_level.upper()))

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(getattr(logging, log_level.upper()))

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S"
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load YAML configuration."""
    with open(config_path) as f:
        return yaml.safe_load(f) or {}


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class TaskResult:
    """Result of executing a single task."""
    task_id: str
    status: str  # PENDING, RUNNING, PASSED, FAILED, BLOCKED, SKIPPED
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    retries: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GateResult:
    """Result of running a validation gate."""
    gate_name: str
    status: str  # PASSED, FAILED
    duration_seconds: float
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PhaseResult:
    """Result of executing a phase."""
    phase_id: int
    name: str
    status: str  # RUNNING, PASSED, FAILED, BLOCKED
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    tasks: List[TaskResult] = field(default_factory=list)
    gate_result: Optional[GateResult] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tasks"] = [t.to_dict() for t in self.tasks]
        if self.gate_result:
            d["gate_result"] = self.gate_result.to_dict()
        return d


@dataclass
class BeastState:
    """Complete state of Beast Mode execution."""
    status: str  # IDLE, RUNNING, PAUSED, COMPLETED, FAILED
    current_phase: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    phases: Dict[int, PhaseResult] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "current_phase": self.current_phase,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "phases": {k: v.to_dict() for k, v in self.phases.items()},
            "errors": self.errors,
        }


# ============================================================================
# Phase and Task Models
# ============================================================================

@dataclass
class Task:
    """Definition of a single task."""
    id: str
    name: str
    prompt: str
    parallel_group: str = "default"
    timeout_minutes: int = 30
    depends_on: List[str] = field(default_factory=list)


@dataclass
class Phase:
    """Definition of a phase."""
    id: int
    name: str
    description: str
    days: str
    tasks: List[Task]


# ============================================================================
# Task Execution
# ============================================================================

class TaskExecutor:
    """Executes individual tasks via Claude Code subprocess."""

    def __init__(
        self,
        fixops_path: str,
        claude_model: str,
        task_timeout_minutes: int,
        max_retries: int,
        logger: logging.Logger,
    ):
        self.fixops_path = os.path.expanduser(fixops_path)
        self.claude_model = claude_model
        self.task_timeout_minutes = task_timeout_minutes
        self.max_retries = max_retries
        self.logger = logger

    async def execute_task(self, task: Task) -> TaskResult:
        """Execute a single task, with retry logic."""
        result = TaskResult(task_id=task.id, status="PENDING")

        for attempt in range(1, self.max_retries + 1):
            result.retries = attempt - 1
            result.status = "RUNNING"
            result.start_time = datetime.utcnow().isoformat() + "Z"

            self.logger.info(f"Executing task {task.id}: {task.name} (attempt {attempt}/{self.max_retries})")

            try:
                # Prepare Claude Code prompt with context
                full_prompt = f"""
You are working on the ALDECI (Fixops) codebase at {self.fixops_path}.

{task.prompt}

Execute this task fully. Make changes, run tests, validate. Report success or failure.
"""

                # Run claude command with --dangerously-skip-permissions
                cmd = [
                    "claude",
                    "--dangerously-skip-permissions",
                    "-p", full_prompt,
                    "-m", self.claude_model,
                ]

                timeout_seconds = task.timeout_minutes * 60

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=timeout_seconds,
                    )

                    if proc.returncode == 0:
                        result.status = "PASSED"
                        result.end_time = datetime.utcnow().isoformat() + "Z"
                        duration = datetime.fromisoformat(result.end_time[:-1]).timestamp() - \
                                  datetime.fromisoformat(result.start_time[:-1]).timestamp()
                        result.duration_seconds = duration
                        self.logger.info(f"Task {task.id} PASSED ({duration:.1f}s)")
                        return result
                    else:
                        error_msg = stderr.decode() if stderr else "Task exited with non-zero status"
                        raise RuntimeError(error_msg)

                except asyncio.TimeoutError:
                    proc.kill()
                    raise RuntimeError(f"Task timeout after {timeout_seconds}s")

            except Exception as e:
                error_str = str(e)
                self.logger.warning(f"Task {task.id} failed (attempt {attempt}): {error_str}")
                result.error_message = error_str

                if attempt < self.max_retries:
                    await asyncio.sleep(5)  # Brief delay before retry
                    continue
                else:
                    result.status = "FAILED"
                    result.end_time = datetime.utcnow().isoformat() + "Z"
                    duration = datetime.fromisoformat(result.end_time[:-1]).timestamp() - \
                              datetime.fromisoformat(result.start_time[:-1]).timestamp()
                    result.duration_seconds = duration
                    self.logger.error(f"Task {task.id} FAILED after {self.max_retries} attempts")
                    return result

        return result


# ============================================================================
# Phase Execution
# ============================================================================

class PhaseExecutor:
    """Executes all tasks in a phase, with parallel concurrency."""

    def __init__(
        self,
        task_executor: TaskExecutor,
        phase_timeout_minutes: int,
        parallel_tasks: int,
        logger: logging.Logger,
    ):
        self.task_executor = task_executor
        self.phase_timeout_minutes = phase_timeout_minutes
        self.parallel_tasks = parallel_tasks
        self.logger = logger

    async def execute_phase(self, phase: Phase) -> PhaseResult:
        """Execute all tasks in a phase."""
        result = PhaseResult(
            phase_id=phase.id,
            name=phase.name,
            status="RUNNING",
            start_time=datetime.utcnow().isoformat() + "Z",
        )

        self.logger.info(f"\n{'='*70}")
        self.logger.info(f"Phase {phase.id}: {phase.name}")
        self.logger.info(f"{'='*70}")

        try:
            # Group tasks by parallel_group
            groups: Dict[str, List[Task]] = {}
            for task in phase.tasks:
                if task.parallel_group not in groups:
                    groups[task.parallel_group] = []
                groups[task.parallel_group].append(task)

            # Execute groups sequentially, tasks within group in parallel
            for group_name in sorted(groups.keys()):
                group_tasks = groups[group_name]
                self.logger.info(f"Executing parallel group '{group_name}' ({len(group_tasks)} tasks)")

                # Run tasks in parallel with concurrency limit
                semaphore = asyncio.Semaphore(self.parallel_tasks)

                async def limited_execute(task: Task) -> TaskResult:
                    async with semaphore:
                        return await self.task_executor.execute_task(task)

                task_results = await asyncio.gather(
                    *[limited_execute(task) for task in group_tasks],
                    return_exceptions=False,
                )

                result.tasks.extend(task_results)

                # Check for failures
                failed = [t for t in task_results if t.status == "FAILED"]
                if failed:
                    self.logger.error(f"Group '{group_name}' had {len(failed)} failures")
                    result.status = "FAILED"
                    result.end_time = datetime.utcnow().isoformat() + "Z"
                    duration = datetime.fromisoformat(result.end_time[:-1]).timestamp() - \
                              datetime.fromisoformat(result.start_time[:-1]).timestamp()
                    result.duration_seconds = duration
                    return result

            # Phase complete
            result.status = "PASSED"
            result.end_time = datetime.utcnow().isoformat() + "Z"
            duration = datetime.fromisoformat(result.end_time[:-1]).timestamp() - \
                      datetime.fromisoformat(result.start_time[:-1]).timestamp()
            result.duration_seconds = duration

            self.logger.info(f"Phase {phase.id} PASSED ({duration:.1f}s)")

        except Exception as e:
            self.logger.error(f"Phase {phase.id} error: {e}")
            result.status = "FAILED"
            result.error_message = str(e)
            result.end_time = datetime.utcnow().isoformat() + "Z"
            duration = datetime.fromisoformat(result.end_time[:-1]).timestamp() - \
                      datetime.fromisoformat(result.start_time[:-1]).timestamp()
            result.duration_seconds = duration

        return result


# ============================================================================
# Validation Gates
# ============================================================================

class ValidationGate:
    """Runs validation gates between phases."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    async def run_gate(self, gate_name: str, command: str) -> GateResult:
        """Run a single gate command."""
        self.logger.info(f"Running gate: {gate_name}")

        start_time = time.time()

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()
            duration = time.time() - start_time

            if proc.returncode == 0:
                self.logger.info(f"Gate {gate_name} PASSED ({duration:.1f}s)")
                return GateResult(
                    gate_name=gate_name,
                    status="PASSED",
                    duration_seconds=duration,
                    details=stdout.decode()[:500],
                )
            else:
                error = stderr.decode()[:500]
                self.logger.error(f"Gate {gate_name} FAILED: {error}")
                return GateResult(
                    gate_name=gate_name,
                    status="FAILED",
                    duration_seconds=duration,
                    details=error,
                )

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Gate {gate_name} error: {e}")
            return GateResult(
                gate_name=gate_name,
                status="FAILED",
                duration_seconds=duration,
                details=str(e),
            )


# ============================================================================
# Main Orchestrator
# ============================================================================

class BeastMode:
    """Main Beast Mode orchestrator."""

    def __init__(self, config_path: Path = None):
        """Initialize Beast Mode."""
        if config_path is None:
            config_path = Path(__file__).parent / "beast.config.yaml"

        self.config = load_config(config_path)
        self.logger = setup_logging(self.config.get("log_level", "INFO"))

        self.state_file = Path(__file__).parent / "logs" / "beast_state.json"
        self.state = self._load_state()

        self.task_executor = TaskExecutor(
            fixops_path=self.config.get("fixops_path", "~/Fixops"),
            claude_model=self.config.get("claude_model", "opus"),
            task_timeout_minutes=self.config.get("task_timeout_minutes", 30),
            max_retries=self.config.get("max_retries", 3),
            logger=self.logger,
        )

        self.phase_executor = PhaseExecutor(
            task_executor=self.task_executor,
            phase_timeout_minutes=self.config.get("phase_timeout_minutes", 120),
            parallel_tasks=self.config.get("parallel_tasks", 4),
            logger=self.logger,
        )

        self.validation_gate = ValidationGate(self.logger)
        self.phases = self._load_phases()
        self.gates = self._load_gates()

        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle graceful shutdown."""
        self.logger.warning("Received SIGINT, saving state and exiting...")
        self._save_state()
        sys.exit(0)

    def _load_state(self) -> BeastState:
        """Load execution state from file."""
        if self.state_file.exists():
            with open(self.state_file) as f:
                data = json.load(f)
                # Reconstruct objects from dict
                state = BeastState(
                    status=data.get("status", "IDLE"),
                    current_phase=data.get("current_phase", 1),
                    start_time=data.get("start_time"),
                    end_time=data.get("end_time"),
                )
                return state

        return BeastState(status="IDLE", current_phase=1)

    def _save_state(self):
        """Save execution state to file."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(self.state.to_dict(), f, indent=2)
        self.logger.debug(f"State saved to {self.state_file}")

    def _load_phases(self) -> Dict[int, Phase]:
        """Load phase definitions from YAML files."""
        phases = {}
        phase_dir = Path(__file__).parent / "phases"

        for i in range(1, 11):
            phase_file = phase_dir / f"phase_{i:02d}.yaml"
            if not phase_file.exists():
                self.logger.warning(f"Phase file {phase_file} not found, skipping")
                continue

            with open(phase_file) as f:
                data = yaml.safe_load(f) or {}

            tasks = []
            for task_data in data.get("tasks", []):
                tasks.append(Task(
                    id=task_data["id"],
                    name=task_data["name"],
                    prompt=task_data["prompt"],
                    parallel_group=task_data.get("parallel_group", "default"),
                    timeout_minutes=task_data.get("timeout_minutes", 30),
                    depends_on=task_data.get("depends_on", []),
                ))

            phases[i] = Phase(
                id=i,
                name=data.get("name", f"Phase {i}"),
                description=data.get("description", ""),
                days=data.get("days", ""),
                tasks=tasks,
            )

        return phases

    def _load_gates(self) -> Dict[int, List[Dict[str, Any]]]:
        """Load gate definitions from YAML."""
        gates_file = Path(__file__).parent / "gates" / "phase_gates.yaml"

        if not gates_file.exists():
            self.logger.warning(f"Gates file {gates_file} not found")
            return {}

        with open(gates_file) as f:
            data = yaml.safe_load(f) or {}

        gates = {}
        for phase_key, phase_gates in data.items():
            phase_id = int(phase_key.replace("phase_", ""))
            gates[phase_id] = phase_gates or []

        return gates

    async def run_gates_for_phase(self, phase_id: int) -> GateResult:
        """Run all gates for a phase."""
        if phase_id not in self.gates:
            return GateResult(
                gate_name="all",
                status="PASSED",
                duration_seconds=0.0,
                details="No gates defined",
            )

        self.logger.info(f"\nRunning validation gates for Phase {phase_id}")

        start_time = time.time()

        for gate_config in self.gates[phase_id]:
            result = await self.validation_gate.run_gate(
                gate_name=gate_config.get("name", "unnamed"),
                command=gate_config.get("command", ""),
            )

            if result.status == "FAILED":
                duration = time.time() - start_time
                return GateResult(
                    gate_name="all",
                    status="FAILED",
                    duration_seconds=duration,
                    details=f"Gate {result.gate_name} failed: {result.details}",
                )

        duration = time.time() - start_time
        return GateResult(
            gate_name="all",
            status="PASSED",
            duration_seconds=duration,
            details="All gates passed",
        )

    async def run_single_phase(self, phase_id: int) -> bool:
        """Execute a single phase with validation gates."""
        if phase_id not in self.phases:
            self.logger.error(f"Phase {phase_id} not found")
            return False

        phase = self.phases[phase_id]

        # Execute phase
        phase_result = await self.phase_executor.execute_phase(phase)
        self.state.phases[phase_id] = phase_result
        self._save_state()

        # Check for phase failure
        if phase_result.status == "FAILED":
            self.logger.error(f"Phase {phase_id} failed, blocking progression")
            return False

        # Run validation gates
        gate_result = await self.run_gates_for_phase(phase_id)
        phase_result.gate_result = gate_result

        if gate_result.status == "FAILED":
            self.logger.error(f"Gates for Phase {phase_id} failed, blocking progression")
            phase_result.status = "BLOCKED"
            self._save_state()
            return False

        self._save_state()
        return True

    async def run_all_phases(self):
        """Run all phases sequentially."""
        self.state.status = "RUNNING"
        self.state.start_time = datetime.utcnow().isoformat() + "Z"
        self._save_state()

        start_phase = self.state.current_phase

        for phase_id in range(start_phase, 11):
            self.state.current_phase = phase_id
            self._save_state()

            success = await self.run_single_phase(phase_id)

            if not success:
                self.logger.error(f"\nBeast Mode halted at Phase {phase_id}")
                self.state.status = "FAILED"
                self.state.end_time = datetime.utcnow().isoformat() + "Z"
                self._save_state()
                return

        self.logger.info("\n" + "="*70)
        self.logger.info("All phases completed successfully!")
        self.logger.info("="*70)

        self.state.status = "COMPLETED"
        self.state.end_time = datetime.utcnow().isoformat() + "Z"
        self._save_state()

    def print_status(self, phase_id: Optional[int] = None):
        """Print current status to console."""
        print("\n" + "="*70)
        print(f"Beast Mode Status: {self.state.status}")
        print(f"Current Phase: {self.state.current_phase}/10")
        print(f"Start Time: {self.state.start_time}")
        print("="*70 + "\n")

        if phase_id:
            phases_to_show = [phase_id]
        else:
            phases_to_show = sorted(self.state.phases.keys())

        for pid in phases_to_show:
            if pid not in self.state.phases:
                continue

            p = self.state.phases[pid]
            print(f"Phase {pid}: {p.name} [{p.status}]")
            print(f"  Duration: {p.duration_seconds:.1f}s")
            print(f"  Tasks: {len(p.tasks)}")

            for task in p.tasks:
                status_icon = {
                    "PASSED": "✓",
                    "FAILED": "✗",
                    "RUNNING": ">",
                    "PENDING": "•",
                }.get(task.status, "?")
                print(f"    [{status_icon}] {task.id}: {task.status} ({task.duration_seconds:.1f}s)")

            if p.gate_result:
                print(f"  Gate: {p.gate_result.status}")
            print()


# ============================================================================
# CLI Interface
# ============================================================================

async def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python beast.py <command>")
        print("  run              Run all phases from current position")
        print("  run-phase <N>    Run single phase N")
        print("  status           Print current status")
        print("  list-phases      List all phases")
        sys.exit(1)

    command = sys.argv[1]

    beast = BeastMode()

    if command == "run":
        await beast.run_all_phases()

    elif command == "run-phase":
        if len(sys.argv) < 3:
            print("Usage: python beast.py run-phase <N>")
            sys.exit(1)
        phase_id = int(sys.argv[2])
        success = await beast.run_single_phase(phase_id)
        sys.exit(0 if success else 1)

    elif command == "status":
        phase_arg = None
        if len(sys.argv) >= 4 and sys.argv[2] == "--phase":
            phase_arg = int(sys.argv[3])
        beast.print_status(phase_arg)

    elif command == "list-phases":
        print("\nAvailable Phases:\n")
        for i in range(1, 11):
            if i in beast.phases:
                p = beast.phases[i]
                print(f"Phase {i}: {p.name}")
                print(f"  Description: {p.description}")
                print(f"  Days: {p.days}")
                print(f"  Tasks: {len(p.tasks)}")
                print()

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
