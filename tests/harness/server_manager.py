"""
ServerManager: Spawns and manages real uvicorn server for E2E API testing.

This component starts a real FastAPI server in a subprocess, waits for it to be ready,
provides the base URL for HTTP requests, and handles clean shutdown.
"""

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests


class ServerManager:
    """Manages a real uvicorn server for E2E testing."""

    _STARTUP_GRACE_SECONDS = 30
    _FATAL_STARTUP_MARKERS = (
        "traceback",
        "error:",
        "exception",
        "address already in use",
        "modulenotfounderror",
        "importerror",
    )
    _PROGRESS_STARTUP_MARKERS = (
        "mounted ",
        "initialized",
        "running in offline mode",
        "using combinedprovider",
        "namespace aliasing enabled",
        "mcp tool catalog ready",
        "api startup complete",
        "all 8 critical route prefixes verified ok",
    )

    @classmethod
    def _should_extend_startup_grace(cls, stderr: str) -> bool:
        """Return True when startup appears slow but still progressing."""
        if not stderr:
            return False

        stderr_lower = stderr.lower()
        if any(marker in stderr_lower for marker in cls._FATAL_STARTUP_MARKERS):
            return False

        return any(marker in stderr_lower for marker in cls._PROGRESS_STARTUP_MARKERS)

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8765,
        app_module: str = "apps.api.app:create_app",
        env: Optional[dict] = None,
        timeout: int = 30,
    ):
        """
        Initialize ServerManager.

        Args:
            host: Host to bind server to
            port: Port to bind server to
            app_module: FastAPI app module path
            env: Environment variables to set for server
            timeout: Timeout in seconds to wait for server to be ready
        """
        self.host = host
        self.port = port
        self.app_module = app_module
        self.env = env or {}
        self.timeout = timeout
        self.process: Optional[subprocess.Popen] = None
        self.base_url = f"http://{host}:{port}"
        self.stdout_file: Optional[tempfile.NamedTemporaryFile] = None
        self.stderr_file: Optional[tempfile.NamedTemporaryFile] = None

    def start(self) -> None:
        """Start the uvicorn server in a subprocess."""
        if self.process is not None:
            raise RuntimeError("Server is already running")

        env = os.environ.copy()
        env.update(self.env)
        env["FIXOPS_DISABLE_TELEMETRY"] = "1"
        env["LAUNCHDARKLY_OFFLINE"] = "1"
        env.pop("LD_SDK_KEY", None)
        env.pop("LD_CLIENT_SIDE_SDK_KEY", None)

        if "FIXOPS_JWT_SECRET" not in env:
            import secrets

            env["FIXOPS_JWT_SECRET"] = secrets.token_hex(32)

        if "FIXOPS_API_TOKEN" not in env:
            import secrets

            env["FIXOPS_API_TOKEN"] = secrets.token_hex(32)

        # Store the actual token used by the server for upload_files method
        self._server_api_token = env["FIXOPS_API_TOKEN"]

        if "FIXOPS_MODE" not in env:
            env["FIXOPS_MODE"] = "enterprise"

        repo_root = Path(__file__).parent.parent.parent
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{repo_root}{os.pathsep}{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = str(repo_root)

        self.stdout_file = tempfile.NamedTemporaryFile(
            mode="w+", delete=False, suffix=".stdout.log"
        )
        self.stderr_file = tempfile.NamedTemporaryFile(
            mode="w+", delete=False, suffix=".stderr.log"
        )

        cmd = [
            "uvicorn",
            self.app_module,
            "--factory",
            "--host",
            self.host,
            "--port",
            str(self.port),
            "--log-level",
            "warning",
        ]

        self.process = subprocess.Popen(
            cmd,
            env=env,
            stdout=self.stdout_file,
            stderr=self.stderr_file,
            text=True,
        )

        self._wait_for_ready()

    def _wait_for_ready(self) -> None:
        """Wait for server to be ready by polling health endpoint."""
        deadline = time.time() + self.timeout
        grace_extended = False

        while True:
            if self.process and self.process.poll() is not None:
                stdout, stderr = self.get_logs()
                error_msg = (
                    f"Server process exited early with code {self.process.returncode}"
                )
                if stderr:
                    error_msg += f"\nStderr: {stderr[:500]}"
                self.stop()
                raise RuntimeError(error_msg)

            try:
                response = requests.get(f"{self.base_url}/api/v1/health", timeout=1)
                if response.status_code == 200:
                    return
            except requests.exceptions.RequestException:
                pass

            if time.time() >= deadline:
                stdout, stderr = self.get_logs()
                if (
                    not grace_extended
                    and self.process is not None
                    and self.process.poll() is None
                    and self._should_extend_startup_grace(stderr)
                ):
                    deadline = time.time() + self._STARTUP_GRACE_SECONDS
                    grace_extended = True
                    continue

                self.stop()
                error_msg = f"Server did not become ready within {self.timeout} seconds"
                if grace_extended:
                    error_msg += (
                        f" (+{self._STARTUP_GRACE_SECONDS}s startup grace)"
                    )
                if stderr:
                    error_msg += f"\nStderr: {stderr[:500]}"
                raise RuntimeError(error_msg)

            time.sleep(0.5)

    def stop(self) -> None:
        """Stop the uvicorn server."""
        if self.process is None:
            return

        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

        self.process = None

        if self.stdout_file:
            self.stdout_file.close()
        if self.stderr_file:
            self.stderr_file.close()

    def get_logs(self) -> tuple[str, str]:
        """Get stdout and stderr logs from the server.

        Reads logs from temporary files to avoid pipe backpressure issues.
        Can be called while server is running or after it has stopped.
        """
        stdout = ""
        stderr = ""

        if self.stdout_file:
            try:
                self.stdout_file.flush()
                self.stdout_file.seek(0)
                stdout = self.stdout_file.read()
            except Exception:
                pass

        if self.stderr_file:
            try:
                self.stderr_file.flush()
                self.stderr_file.seek(0)
                stderr = self.stderr_file.read()
            except Exception:
                pass

        return stdout, stderr

    def upload_files(
        self,
        sast: Optional[str] = None,
        sbom: Optional[str] = None,
        cve: Optional[str] = None,
        design: Optional[str] = None,
        cnapp: Optional[str] = None,
        context: Optional[str] = None,
    ) -> requests.Response:
        """
        Upload files to the API and trigger pipeline execution.

        Args:
            sast: Path to SAST/SARIF file
            sbom: Path to SBOM JSON file
            cve: Path to CVE JSON file
            design: Path to design CSV file
            cnapp: Path to CNAPP JSON file (cloud exposure data)
            context: Path to context JSON file

        Returns:
            Response from pipeline/run endpoint

        Raises:
            requests.HTTPError: If any upload or pipeline request fails
        """
        # Use the server's actual API token (generated in start() if not provided)
        api_token = getattr(self, "_server_api_token", None) or self.env.get(
            "FIXOPS_API_TOKEN", ""
        )
        headers = {"X-API-Key": api_token}

        # Upload each file to its respective endpoint
        file_mappings = {
            "sarif": sast,
            "sbom": sbom,
            "cve": cve,
            "design": design,
        }

        for endpoint, file_path in file_mappings.items():
            if file_path:
                with open(file_path, "rb") as f:
                    content = f.read()
                    content_type = (
                        "application/json"
                        if file_path.endswith(".json")
                        else "text/csv"
                    )
                    files = {"file": (Path(file_path).name, content, content_type)}
                    resp = requests.post(
                        f"{self.base_url}/inputs/{endpoint}",
                        files=files,
                        headers=headers,
                        timeout=30,
                    )
                    resp.raise_for_status()

        # Upload CNAPP data if provided (cloud exposure information)
        if cnapp:
            with open(cnapp, "r") as f:
                cnapp_data = f.read()
            resp = requests.post(
                f"{self.base_url}/api/v1/context/cnapp",
                data=cnapp_data,
                headers={**headers, "Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()

        # Upload context data if provided
        if context:
            with open(context, "r") as f:
                context_data = f.read()
            resp = requests.post(
                f"{self.base_url}/api/v1/context",
                data=context_data,
                headers={**headers, "Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()

        # Trigger pipeline execution and return response
        response = requests.get(
            f"{self.base_url}/pipeline/run",
            headers=headers,
            timeout=60,
        )

        return response

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
