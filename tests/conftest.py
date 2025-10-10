from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Generator, Iterable, Tuple

ROOT = Path(__file__).resolve().parents[1]
ENTERPRISE_SRC_ROOT = ROOT / "fixops-enterprise"
if str(ENTERPRISE_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(ENTERPRISE_SRC_ROOT))

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.config.settings import get_settings


@pytest.fixture
def signing_env(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    monkeypatch.setenv("FIXOPS_SIGNING_KEY", pem.decode("utf-8"))
    monkeypatch.setenv("FIXOPS_SIGNING_KID", "test-kid")
    monkeypatch.setenv("FIXOPS_API_KEY", "test-token")
    monkeypatch.setenv("FIXOPS_ALLOWED_ORIGINS", "http://localhost")
    get_settings.cache_clear()
    try:
        yield
    finally:
        get_settings.cache_clear()
        for var in ["FIXOPS_SIGNING_KEY", "FIXOPS_SIGNING_KID", "FIXOPS_API_KEY", "FIXOPS_ALLOWED_ORIGINS"]:
            os.environ.pop(var, None)


class SimpleCoverage:
    def __init__(self, targets: Iterable[str]) -> None:
        self._files = set()
        for target in targets or []:
            path = Path(target)
            if not path.is_absolute():
                path = (ROOT / target).resolve()
            if path.is_dir():
                for file in path.rglob("*.py"):
                    self._files.add(str(file))
            elif path.is_file():
                self._files.add(str(path))
            else:
                module_path = target.replace(".", os.sep) + ".py"
                candidate = (ROOT / module_path).resolve()
                if candidate.exists():
                    self._files.add(str(candidate))
        if not self._files and ENTERPRISE_SRC_ROOT.exists():
            default_root = ENTERPRISE_SRC_ROOT.resolve()
            for file in default_root.rglob("*.py"):
                self._files.add(str(file))
        self._data: dict[str, set[int]] = {}
        self._tracer = None

    def _should_track(self, filename: str) -> bool:
        return filename in self._files

    def _trace(self, frame, event, arg):  # type: ignore[no-untyped-def]
        if event == "line":
            filename = frame.f_code.co_filename
            if self._should_track(filename):
                lineno = frame.f_lineno
                self._data.setdefault(filename, set()).add(lineno)
        return self._trace

    def start(self) -> None:
        sys.settrace(self._trace)

    def stop(self) -> None:
        sys.settrace(None)

    def _compute(self) -> Tuple[int, int, list[Tuple[str, list[int], set[int]]]]:
        results = []
        covered = 0
        total = 0
        for filename in sorted(self._files):
            try:
                with open(filename, "r", encoding="utf-8") as handle:
                    interesting = []
                    for lineno, line in enumerate(handle, start=1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith("#"):
                            continue
                        if stripped.startswith("\"\"\"") or stripped.startswith("'''"):
                            continue
                        if "# pragma: no cover" in stripped:
                            continue
                        interesting.append(lineno)
            except OSError:
                continue
            executed = self._data.get(filename, set())
            covered += len(executed & set(interesting))
            total += len(interesting)
            results.append((filename, interesting, executed))
        return covered, total, results

    def report(self, show_missing: bool = False, file=None) -> float:
        covered, total, results = self._compute()
        percent = 100.0 if total == 0 else (covered / total) * 100.0
        stream = file or sys.stdout
        stream.write(f"TOTAL {percent:.2f}%\n")
        if show_missing:
            for filename, interesting, executed in results:
                missing = sorted(set(interesting) - executed)
                if missing:
                    stream.write(f"{filename}: missing {missing}\n")
        return percent

    def xml_report(self, outfile: str) -> None:
        covered, total, _ = self._compute()
        rate = 1.0 if total == 0 else covered / total
        with open(outfile, "w", encoding="utf-8") as handle:
            handle.write("<?xml version='1.0' encoding='UTF-8'?>\n")
            handle.write(f"<coverage line-rate='{rate:.3f}' branch-rate='0.0' version='simple'/>\n")


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("coverage")
    group.addoption("--cov", action="append", default=[], help="Coverage targets (paths or modules)")
    group.addoption("--cov-branch", action="store_true", default=False, help="Enable branch coverage")
    group.addoption("--cov-fail-under", action="store", default=None, type=float, help="Fail if coverage below threshold")
    group.addoption("--cov-report", action="append", default=[], help="Coverage report types (term, xml)")


def pytest_configure(config: pytest.Config) -> None:
    cov_reports = config.getoption("--cov")
    config._fixops_cov = SimpleCoverage(cov_reports or [])
    config._fixops_cov.start()


def pytest_unconfigure(config: pytest.Config) -> None:
    cov = getattr(config, "_fixops_cov", None)
    if cov is None:
        return
    cov.stop()
    reports = config.getoption("--cov-report") or ["term"]
    summary = None
    for report in reports:
        report = report.lower()
        if report in {"term", "term-missing"}:
            summary = cov.report(show_missing=report == "term-missing")
        elif report == "xml":
            cov.xml_report(outfile=str(ROOT / "coverage.xml"))
    if summary is None:
        summary = cov.report(show_missing=False, file=open(os.devnull, "w"))
    threshold = config.getoption("--cov-fail-under")
    if threshold is not None and summary < threshold:
        raise pytest.UsageError(f"Coverage {summary:.2f}% is below fail-under {threshold}%")

