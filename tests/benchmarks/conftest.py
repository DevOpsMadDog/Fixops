"""
Benchmark conftest — registers the 'benchmark' marker so that
`pytest -m benchmark` selects only perf-lockdown tests.
"""
import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "benchmark: performance lockdown tests — run with `pytest -m benchmark`",
    )
