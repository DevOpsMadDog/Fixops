"""
ServerManager: Spawns and manages real uvicorn server for E2E API testing.

This component starts a real FastAPI server in a subprocess, waits for it to be ready,
provides the base URL for HTTP requests, and handles clean shutdown.
"""

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

import requests


class ServerManager:
    """Manages a real uvicorn server for E2E testing."""

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

    def start(self) -> None:
        """Start the uvicorn server in a subprocess."""
        if self.process is not None:
            raise RuntimeError("Server is already running")

        env = os.environ.copy()
        env.update(self.env)
        env["FIXOPS_DISABLE_TELEMETRY"] = "1"

        repo_root = Path(__file__).parent.parent.parent
        if "PYTHONPATH" in env:
            env["PYTHONPATH"] = f"{repo_root}:{env['PYTHONPATH']}"
        else:
            env["PYTHONPATH"] = str(repo_root)

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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self._wait_for_ready()

    def _wait_for_ready(self) -> None:
        """Wait for server to be ready by polling health endpoint."""
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            try:
                response = requests.get(f"{self.base_url}/api/v1/health", timeout=1)
                if response.status_code == 200:
                    return
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.5)

        self.stop()
        raise RuntimeError(f"Server did not become ready within {self.timeout} seconds")

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

    def get_logs(self) -> tuple[str, str]:
        """Get stdout and stderr logs from the server."""
        if self.process is None:
            return "", ""

        stdout = self.process.stdout.read() if self.process.stdout else ""
        stderr = self.process.stderr.read() if self.process.stderr else ""
        return stdout, stderr

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
