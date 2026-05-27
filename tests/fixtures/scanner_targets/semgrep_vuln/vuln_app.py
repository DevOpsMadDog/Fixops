"""Fixture file for semgrep real-binary integration tests.

Contains deliberately vulnerable Python patterns that real semgrep rules
flag.  This file is INTENTIONALLY insecure — do not use in production.

Patterns present:
  - eval(input(...))           → exec/eval injection (CWE-95)
  - os.system(user_input)     → OS command injection (CWE-78)
  - subprocess with shell=True → shell injection (CWE-78)
"""
import os
import subprocess


def process_user_command(user_input: str) -> None:
    # VULN: eval of user input — semgrep python.lang.security.audit.eval-detected
    eval(user_input)  # noqa: S307


def run_system_command(cmd: str) -> int:
    # VULN: os.system with user-controlled input — command injection
    return os.system(cmd)  # noqa: S605


def run_subprocess_shell(cmd: str) -> str:
    # VULN: subprocess with shell=True — shell injection
    result = subprocess.run(cmd, shell=True, capture_output=True)  # noqa: S602
    return result.stdout.decode()
