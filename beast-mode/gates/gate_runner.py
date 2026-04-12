#!/usr/bin/env python3
"""Gate Runner — Validation gate executor for Beast Mode phases.

Runs automated checks (tests, lint, type checks, builds) between phases
to ensure code quality before progression.
"""

import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# ============================================================================
# Gate Result Model
# ============================================================================

@dataclass
class GateResult:
    """Result of running a validation gate."""
    gate_name: str
    gate_type: str
    status: str  # PASSED, FAILED, SKIPPED
    duration_seconds: float
    details: str
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate_name": self.gate_name,
            "gate_type": self.gate_type,
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "details": self.details[:500],  # Truncate for logging
            "error_message": self.error_message[:500] if self.error_message else None,
        }


# ============================================================================
# Gate Runner
# ============================================================================

class GateRunner:
    """Executes validation gates for phases."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    async def run_gate(
        self,
        gate_name: str,
        gate_type: str,
        command: str,
        timeout_seconds: int = 300,
        description: str = None,
    ) -> GateResult:
        """Run a single validation gate.

        Args:
            gate_name: Human-readable gate name
            gate_type: Type of gate (test, lint, type, build, persona, custom)
            command: Shell command to execute
            timeout_seconds: Gate timeout in seconds
            description: Optional description of what the gate checks

        Returns:
            GateResult with status and details
        """
        self.logger.info(f"Running {gate_type} gate: {gate_name}")
        if description:
            self.logger.debug(f"  Description: {description}")

        start_time = time.time()

        try:
            # Run command with timeout
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_seconds,
                )

                duration = time.time() - start_time
                output = stdout.decode() if stdout else ""
                error_output = stderr.decode() if stderr else ""

                if proc.returncode == 0:
                    self.logger.info(f"Gate {gate_name} PASSED ({duration:.1f}s)")
                    return GateResult(
                        gate_name=gate_name,
                        gate_type=gate_type,
                        status="PASSED",
                        duration_seconds=duration,
                        details=output,
                    )
                else:
                    self.logger.error(f"Gate {gate_name} FAILED ({duration:.1f}s)")
                    return GateResult(
                        gate_name=gate_name,
                        gate_type=gate_type,
                        status="FAILED",
                        duration_seconds=duration,
                        details=error_output,
                        error_message=f"Exit code: {proc.returncode}",
                    )

            except asyncio.TimeoutError:
                proc.kill()
                duration = time.time() - start_time
                self.logger.error(f"Gate {gate_name} TIMEOUT after {timeout_seconds}s")
                return GateResult(
                    gate_name=gate_name,
                    gate_type=gate_type,
                    status="FAILED",
                    duration_seconds=duration,
                    details="",
                    error_message=f"Timeout after {timeout_seconds}s",
                )

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Gate {gate_name} ERROR: {e}")
            return GateResult(
                gate_name=gate_name,
                gate_type=gate_type,
                status="FAILED",
                duration_seconds=duration,
                details="",
                error_message=str(e),
            )

    async def run_test_gate(
        self,
        gate_name: str,
        test_path: str,
        timeout_seconds: int = 300,
    ) -> GateResult:
        """Run pytest tests as a gate."""
        command = f"cd ~/Fixops && python -m pytest {test_path} -v --tb=short"
        return await self.run_gate(
            gate_name=gate_name,
            gate_type="test",
            command=command,
            timeout_seconds=timeout_seconds,
            description=f"Running pytest on {test_path}",
        )

    async def run_lint_gate(
        self,
        gate_name: str,
        path: str,
        timeout_seconds: int = 120,
    ) -> GateResult:
        """Run ruff linter as a gate."""
        command = f"cd ~/Fixops && ruff check {path}"
        return await self.run_gate(
            gate_name=gate_name,
            gate_type="lint",
            command=command,
            timeout_seconds=timeout_seconds,
            description=f"Running ruff linter on {path}",
        )

    async def run_type_gate(
        self,
        gate_name: str,
        path: str,
        timeout_seconds: int = 180,
    ) -> GateResult:
        """Run type checker (mypy/pyright) as a gate."""
        command = f"cd ~/Fixops && python -m mypy {path} --ignore-missing-imports"
        return await self.run_gate(
            gate_name=gate_name,
            gate_type="type",
            command=command,
            timeout_seconds=timeout_seconds,
            description=f"Running mypy type checker on {path}",
        )

    async def run_build_gate(
        self,
        gate_name: str,
        dockerfile: str = "Dockerfile",
        timeout_seconds: int = 600,
    ) -> GateResult:
        """Run Docker build as a gate."""
        command = f"cd ~/Fixops && docker build -f {dockerfile} ."
        return await self.run_gate(
            gate_name=gate_name,
            gate_type="build",
            command=command,
            timeout_seconds=timeout_seconds,
            description=f"Building Docker image from {dockerfile}",
        )

    async def run_persona_gate(
        self,
        gate_name: str,
        persona_id: str,
        timeout_seconds: int = 300,
    ) -> GateResult:
        """Run persona E2E tests as a gate."""
        command = (
            f"cd ~/Fixops && python -m pytest tests/e2e/personas/{persona_id}.py "
            "-v --tb=short --timeout=30"
        )
        return await self.run_gate(
            gate_name=gate_name,
            gate_type="persona",
            command=command,
            timeout_seconds=timeout_seconds,
            description=f"Running E2E tests for persona '{persona_id}'",
        )

    async def run_custom_gate(
        self,
        gate_name: str,
        command: str,
        timeout_seconds: int = 300,
    ) -> GateResult:
        """Run a custom gate command."""
        return await self.run_gate(
            gate_name=gate_name,
            gate_type="custom",
            command=command,
            timeout_seconds=timeout_seconds,
            description="Custom validation gate",
        )

    async def run_multiple_gates(
        self,
        gates: List[Dict[str, Any]],
        stop_on_first_failure: bool = True,
    ) -> List[GateResult]:
        """Run multiple gates, optionally stopping on first failure.

        Args:
            gates: List of gate definitions with 'name', 'type', 'command' keys
            stop_on_first_failure: If True, stop running gates after first failure

        Returns:
            List of GateResult objects
        """
        results = []

        for gate_config in gates:
            gate_name = gate_config.get("name", "unnamed")
            gate_type = gate_config.get("type", "custom")
            command = gate_config.get("command", "")
            timeout = gate_config.get("timeout_seconds", 300)

            result = await self.run_gate(
                gate_name=gate_name,
                gate_type=gate_type,
                command=command,
                timeout_seconds=timeout,
            )

            results.append(result)

            if result.status == "FAILED" and stop_on_first_failure:
                self.logger.warning(f"First failure detected in {gate_name}, stopping")
                break

        return results


# ============================================================================
# Convenience function
# ============================================================================

async def run_phase_gates(
    phase_id: int,
    gates: List[Dict[str, Any]],
    logger: logging.Logger,
) -> bool:
    """Run all gates for a phase.

    Args:
        phase_id: Phase ID for logging context
        gates: List of gate definitions
        logger: Logger instance

    Returns:
        True if all gates passed, False if any failed
    """
    runner = GateRunner(logger)
    results = await runner.run_multiple_gates(gates, stop_on_first_failure=True)

    passed = sum(1 for r in results if r.status == "PASSED")
    failed = sum(1 for r in results if r.status == "FAILED")

    logger.info(f"Phase {phase_id} gates: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    # Simple test
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("GateRunner")

    async def test():
        runner = GateRunner(logger)
        result = await runner.run_test_gate(
            gate_name="Sample Tests",
            test_path="tests/test_sample.py",
        )
        print(f"Result: {result.to_dict()}")

    asyncio.run(test())
