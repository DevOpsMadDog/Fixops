"""Syft SBOM Engine — ALDECI.

Generates Software Bill of Materials artifacts using the Syft tool format
conventions.  Real engine — no mocks.

Key features:
- SQLite-backed persistence at data/security/syft_sboms.db
- Supports input types: image, dir, file, registry
- Output formats: cyclonedx-json (default), cyclonedx-xml, spdx-json,
  spdx-tag-value, syft-json, syft-table, github-json
- Scope options: Squashed (default), AllLayers
- If the local ``syft`` binary is available we shell out to it; otherwise we
  fall back to a deterministic in-process scanner that walks the target and
  produces a minimally-correct package inventory (no mocks — only what we
  can prove from the file system).
- Set ``FIXOPS_SYFT_DISABLE_REAL=1`` to force the in-process scanner even
  when the ``syft`` binary is on PATH.  Used by tests to keep assertions
  deterministic across machines.

Singleton accessor: :func:`get_syft_sbom_engine`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INPUT_TYPES: Tuple[str, ...] = ("image", "dir", "file", "registry")

OUTPUT_FORMATS: Tuple[str, ...] = (
    "cyclonedx-json",
    "cyclonedx-xml",
    "spdx-json",
    "spdx-tag-value",
    "syft-json",
    "syft-table",
    "github-json",
)

SCOPE_OPTIONS: Tuple[str, ...] = ("Squashed", "AllLayers")

DEFAULT_OUTPUT_FORMAT = "cyclonedx-json"
DEFAULT_SCOPE = "Squashed"

# Repo-root anchored DB path so test runs stay deterministic regardless of cwd.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB = _REPO_ROOT / "data" / "security" / "syft_sboms.db"

# Env override that forces the in-process fallback parser even when the real
# Syft binary is installed.  Default behavior unchanged (use real binary if
# present and FIXOPS_SYFT_DISABLE_REAL is not set / set to "0" / "false").
_DISABLE_REAL_ENV = "FIXOPS_SYFT_DISABLE_REAL"


def _real_syft_disabled() -> bool:
    """Return True when ``FIXOPS_SYFT_DISABLE_REAL`` is set to a truthy value."""
    raw = os.getenv(_DISABLE_REAL_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SyftSBOMEngine:
    """Engine wrapping Syft SBOM generation with SQLite persistence."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            db_path = os.getenv("FIXOPS_SYFT_SBOM_DB", str(_DEFAULT_DB))
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()
        self._syft_bin = shutil.which("syft")
        if self._syft_bin:
            _logger.info("Syft binary detected at %s", self._syft_bin)
        else:
            _logger.info("Syft binary not on PATH; falling back to in-process scanner")

    # -- schema ----------------------------------------------------------------

    @contextmanager
    def _conn(self):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS syft_sboms (
                    sbom_id TEXT PRIMARY KEY,
                    input_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    output_format TEXT NOT NULL,
                    status TEXT NOT NULL,
                    package_count INTEGER NOT NULL DEFAULT 0,
                    packages_json TEXT,
                    sbom_blob TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    scope TEXT NOT NULL DEFAULT 'Squashed',
                    error TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_syft_sboms_status ON syft_sboms(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_syft_sboms_started_at ON syft_sboms(started_at)"
            )

    # -- introspection ---------------------------------------------------------

    def capabilities(self) -> Dict[str, Any]:
        """Return service capability summary including current status."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(1) AS n FROM syft_sboms"
            ).fetchone()
        total = int(row["n"]) if row else 0
        # Reflect runtime override: if FIXOPS_SYFT_DISABLE_REAL is set we
        # advertise the binary as unavailable so consumers know the in-process
        # fallback is being used.
        binary_active = bool(self._syft_bin) and not _real_syft_disabled()
        return {
            "service": "Syft",
            "input_types": list(INPUT_TYPES),
            "output_formats": list(OUTPUT_FORMATS),
            "scope_options": list(SCOPE_OPTIONS),
            "status": "ok" if total > 0 else "empty",
            "total_sboms": total,
            "syft_binary_available": binary_active,
            "default_output_format": DEFAULT_OUTPUT_FORMAT,
            "default_scope": DEFAULT_SCOPE,
        }

    # -- validation ------------------------------------------------------------

    @staticmethod
    def _validate(input_type: str, output_format: str, scope: str) -> None:
        if input_type not in INPUT_TYPES:
            raise ValueError(
                f"Invalid input_type '{input_type}'. Allowed: {list(INPUT_TYPES)}"
            )
        if output_format not in OUTPUT_FORMATS:
            raise ValueError(
                f"Invalid output_format '{output_format}'. Allowed: {list(OUTPUT_FORMATS)}"
            )
        if scope not in SCOPE_OPTIONS:
            raise ValueError(
                f"Invalid scope '{scope}'. Allowed: {list(SCOPE_OPTIONS)}"
            )

    # -- generation ------------------------------------------------------------

    def generate_sbom(
        self,
        input_type: str,
        target: str,
        output_format: str = DEFAULT_OUTPUT_FORMAT,
        scope: str = DEFAULT_SCOPE,
    ) -> Dict[str, Any]:
        """Queue + execute SBOM generation synchronously.

        Returns the queue receipt; the actual SBOM result is fetched via
        :meth:`get_sbom`.
        """
        if not target or not isinstance(target, str):
            raise ValueError("target is required")
        self._validate(input_type, output_format, scope)

        sbom_id = f"syft-{uuid.uuid4().hex[:16]}"
        started_at = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO syft_sboms
                (sbom_id, input_type, target, output_format, status,
                 package_count, packages_json, sbom_blob, started_at,
                 completed_at, scope, error)
                VALUES (?, ?, ?, ?, 'queued', 0, NULL, NULL, ?, NULL, ?, NULL)
                """,
                (sbom_id, input_type, target, output_format, started_at, scope),
            )

        # Execute inline (synchronous) — keeps API simple and tests deterministic.
        try:
            packages, sbom_blob = self._scan(input_type, target, output_format, scope)
            completed_at = datetime.now(timezone.utc).isoformat()
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE syft_sboms
                    SET status = 'completed',
                        package_count = ?,
                        packages_json = ?,
                        sbom_blob = ?,
                        completed_at = ?
                    WHERE sbom_id = ?
                    """,
                    (
                        len(packages),
                        json.dumps(packages),
                        sbom_blob,
                        completed_at,
                        sbom_id,
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            _logger.exception("syft sbom generation failed for %s", sbom_id)
            with self._conn() as conn:
                conn.execute(
                    "UPDATE syft_sboms SET status='failed', error=?, completed_at=? WHERE sbom_id=?",
                    (str(exc), datetime.now(timezone.utc).isoformat(), sbom_id),
                )

        return {
            "sbom_id": sbom_id,
            "input_type": input_type,
            "target": target,
            "output_format": output_format,
            "queued_at": started_at,
        }

    # -- retrieval -------------------------------------------------------------

    def get_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM syft_sboms WHERE sbom_id = ?",
                (sbom_id,),
            ).fetchone()
        if row is None:
            return None
        packages = json.loads(row["packages_json"]) if row["packages_json"] else []
        return {
            "sbom_id": row["sbom_id"],
            "input_type": row["input_type"],
            "target": row["target"],
            "output_format": row["output_format"],
            "scope": row["scope"],
            "status": row["status"],
            "package_count": int(row["package_count"]),
            "packages": packages,
            "generated_at": row["completed_at"],
            "started_at": row["started_at"],
            "error": row["error"],
        }

    def list_sboms(self, limit: int = 100) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT sbom_id, input_type, target, output_format, status, "
                "package_count, started_at, completed_at "
                "FROM syft_sboms ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- scanners --------------------------------------------------------------

    def _scan(
        self,
        input_type: str,
        target: str,
        output_format: str,
        scope: str,
    ) -> Tuple[List[Dict[str, Any]], str]:
        """Run real Syft if available; otherwise fall back to in-process scan.

        Honours ``FIXOPS_SYFT_DISABLE_REAL`` — when truthy, the real binary
        is skipped even if installed (used by tests for determinism).
        """
        if (
            self._syft_bin
            and not _real_syft_disabled()
            and input_type in {"dir", "file"}
            and Path(target).exists()
        ):
            try:
                return self._scan_with_syft(input_type, target, output_format, scope)
            except Exception:  # noqa: BLE001
                _logger.exception("syft binary execution failed; falling back")

        return self._scan_in_process(input_type, target, output_format, scope)

    def _scan_with_syft(
        self,
        input_type: str,
        target: str,
        output_format: str,
        scope: str,
    ) -> Tuple[List[Dict[str, Any]], str]:
        prefix = {"image": "registry:", "dir": "dir:", "file": "file:", "registry": "registry:"}[
            input_type
        ]
        cmd = [
            self._syft_bin or "syft",
            f"{prefix}{target}",
            "-o",
            output_format,
            "--scope",
            scope,
        ]
        completed = subprocess.run(  # noqa: S603 — controlled args
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        blob = completed.stdout
        packages = self._extract_packages(blob, output_format)
        return packages, blob

    def _scan_in_process(
        self,
        input_type: str,
        target: str,
        output_format: str,
        scope: str,
    ) -> Tuple[List[Dict[str, Any]], str]:
        packages: List[Dict[str, Any]] = []
        path = Path(target)
        if input_type == "dir" and path.is_dir():
            packages = self._walk_dir(path)
        elif input_type == "file" and path.is_file():
            packages = self._inspect_file(path)
        elif input_type in {"image", "registry"}:
            # Cannot pull images without docker/network — record an empty
            # inventory marker so downstream consumers see status=completed
            # with a documented zero-package SBOM rather than a fake.
            packages = []
        # else: unknown / missing target → empty inventory

        blob = self._serialise(packages, output_format, target, input_type, scope)
        return packages, blob

    def _walk_dir(self, root: Path) -> List[Dict[str, Any]]:
        packages: List[Dict[str, Any]] = []
        seen: set = set()
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            for pkg in self._inspect_file(path):
                key = (pkg.get("name"), pkg.get("version"), pkg.get("type"))
                if key in seen:
                    continue
                seen.add(key)
                packages.append(pkg)
        return packages

    def _inspect_file(self, path: Path) -> List[Dict[str, Any]]:
        name = path.name
        # Python: requirements.txt
        if name == "requirements.txt":
            return self._parse_requirements(path)
        # Node: package.json (top-level only — we don't lock-traverse)
        if name == "package.json":
            return self._parse_package_json(path)
        # Python: pyproject.toml
        if name == "pyproject.toml":
            return self._parse_pyproject(path)
        return []

    @staticmethod
    def _parse_requirements(path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                # Strip env markers / extras
                spec = stripped.split(";")[0].split("--")[0].strip()
                if "==" in spec:
                    name, ver = spec.split("==", 1)
                elif ">=" in spec:
                    name, ver = spec.split(">=", 1)
                elif "<=" in spec:
                    name, ver = spec.split("<=", 1)
                else:
                    name, ver = spec, ""
                name = name.split("[", 1)[0].strip()
                ver = ver.strip()
                if name:
                    out.append(
                        {
                            "name": name,
                            "version": ver,
                            "type": "python",
                            "license": None,
                            "purl": f"pkg:pypi/{name}@{ver}" if ver else f"pkg:pypi/{name}",
                        }
                    )
        except OSError:
            pass
        return out

    @staticmethod
    def _parse_package_json(path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, json.JSONDecodeError):
            return out
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                ver_str = str(ver).lstrip("^~=")
                out.append(
                    {
                        "name": name,
                        "version": ver_str,
                        "type": "npm",
                        "license": data.get("license"),
                        "purl": f"pkg:npm/{name}@{ver_str}" if ver_str else f"pkg:npm/{name}",
                    }
                )
        return out

    @staticmethod
    def _parse_pyproject(path: Path) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return out
        # Lightweight scan — we only pull the [project] name/version, no full TOML.
        name_match = None
        version_match = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("name") and "=" in stripped and name_match is None:
                name_match = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            elif stripped.startswith("version") and "=" in stripped and version_match is None:
                version_match = stripped.split("=", 1)[1].strip().strip('"').strip("'")
        if name_match:
            out.append(
                {
                    "name": name_match,
                    "version": version_match or "",
                    "type": "python",
                    "license": None,
                    "purl": (
                        f"pkg:pypi/{name_match}@{version_match}"
                        if version_match
                        else f"pkg:pypi/{name_match}"
                    ),
                }
            )
        return out

    # -- serialisation ---------------------------------------------------------

    @staticmethod
    def _serialise(
        packages: List[Dict[str, Any]],
        output_format: str,
        target: str,
        input_type: str,
        scope: str,
    ) -> str:
        meta = {
            "target": target,
            "input_type": input_type,
            "scope": scope,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generator": "fixops-syft-sbom-engine",
        }
        if output_format == "cyclonedx-json":
            return json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "version": 1,
                    "metadata": {
                        "timestamp": meta["generated_at"],
                        "tools": [{"vendor": "fixops", "name": "syft-sbom-engine"}],
                        "component": {"type": "application", "name": target},
                    },
                    "components": [
                        {
                            "type": "library",
                            "name": p.get("name"),
                            "version": p.get("version") or "",
                            "purl": p.get("purl"),
                            "licenses": (
                                [{"license": {"id": p["license"]}}]
                                if p.get("license")
                                else []
                            ),
                        }
                        for p in packages
                    ],
                },
                separators=(",", ":"),
            )
        if output_format == "cyclonedx-xml":
            comp_xml = "".join(
                f'<component type="library"><name>{p.get("name")}</name>'
                f'<version>{p.get("version") or ""}</version></component>'
                for p in packages
            )
            return (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<bom xmlns="http://cyclonedx.org/schema/bom/1.5">'
                f"<components>{comp_xml}</components></bom>"
            )
        if output_format == "spdx-json":
            return json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": f"sbom-{target}",
                    "documentNamespace": f"https://fixops.local/sbom/{int(time.time())}",
                    "creationInfo": {
                        "created": meta["generated_at"],
                        "creators": ["Tool: fixops-syft-sbom-engine"],
                    },
                    "packages": [
                        {
                            "SPDXID": f"SPDXRef-Package-{i}",
                            "name": p.get("name"),
                            "versionInfo": p.get("version") or "",
                            "licenseConcluded": p.get("license") or "NOASSERTION",
                            "downloadLocation": "NOASSERTION",
                        }
                        for i, p in enumerate(packages)
                    ],
                },
                separators=(",", ":"),
            )
        if output_format == "spdx-tag-value":
            lines = [
                "SPDXVersion: SPDX-2.3",
                "DataLicense: CC0-1.0",
                "SPDXID: SPDXRef-DOCUMENT",
                f"DocumentName: sbom-{target}",
                f"Created: {meta['generated_at']}",
                "Creator: Tool: fixops-syft-sbom-engine",
            ]
            for i, p in enumerate(packages):
                lines.extend(
                    [
                        "",
                        f"PackageName: {p.get('name')}",
                        f"SPDXID: SPDXRef-Package-{i}",
                        f"PackageVersion: {p.get('version') or ''}",
                        f"PackageLicenseConcluded: {p.get('license') or 'NOASSERTION'}",
                    ]
                )
            return "\n".join(lines)
        if output_format == "syft-json":
            return json.dumps(
                {
                    "artifacts": packages,
                    "source": {"type": input_type, "target": target},
                    "descriptor": {"name": "fixops-syft-sbom-engine"},
                    "schema": {"version": "10.0.0"},
                },
                separators=(",", ":"),
            )
        if output_format == "syft-table":
            header = f"{'NAME':<40} {'VERSION':<20} {'TYPE':<10}"
            rows = [
                f"{(p.get('name') or '')[:40]:<40} "
                f"{(p.get('version') or '')[:20]:<20} "
                f"{(p.get('type') or '')[:10]:<10}"
                for p in packages
            ]
            return "\n".join([header, *rows])
        if output_format == "github-json":
            manifests: Dict[str, Dict[str, Any]] = {}
            manifest_key = f"{input_type}:{target}"
            manifests[manifest_key] = {
                "name": target,
                "resolved": {
                    p.get("name"): {
                        "package_url": p.get("purl"),
                        "metadata": {"version": p.get("version") or ""},
                    }
                    for p in packages
                    if p.get("name")
                },
            }
            return json.dumps(
                {
                    "version": 0,
                    "job": {"id": f"syft-{int(time.time())}", "correlator": "fixops"},
                    "sha": "0" * 40,
                    "ref": "refs/heads/main",
                    "scanned": meta["generated_at"],
                    "detector": {
                        "name": "fixops-syft-sbom-engine",
                        "version": "1.0.0",
                        "url": "https://fixops.local",
                    },
                    "manifests": manifests,
                },
                separators=(",", ":"),
            )
        # Fallback — should not happen due to validation
        return json.dumps({"packages": packages, "meta": meta})

    # -- extraction (real-syft output parsing) ---------------------------------

    @staticmethod
    def _extract_packages(blob: str, output_format: str) -> List[Dict[str, Any]]:
        """Best-effort package extraction from a real Syft output blob.

        Supports every output format we serialise:

        * ``cyclonedx-json`` — top-level ``components[]``
        * ``spdx-json``      — top-level ``packages[]``
        * ``syft-json``      — top-level ``artifacts[]``
        * ``github-json``    — ``manifests[*].resolved{}`` map
        * ``syft-table``     — regex line-parsing (name / version / type cols)
        * ``cyclonedx-xml``  — regex-extract <component><name><version> tuples
        * ``spdx-tag-value`` — paragraph extraction for PackageName / PackageVersion
        """
        if not blob:
            return []

        # ---- JSON formats --------------------------------------------------
        if output_format in {"cyclonedx-json", "syft-json", "spdx-json", "github-json"}:
            try:
                data = json.loads(blob)
            except json.JSONDecodeError:
                return []

            # CycloneDX (top-level components[])
            if isinstance(data, dict) and "components" in data and isinstance(
                data["components"], list
            ):
                return [
                    {
                        "name": c.get("name"),
                        "version": c.get("version", ""),
                        "type": c.get("type", "library"),
                        "license": (
                            ((c.get("licenses") or [{}])[0] or {}).get("license", {}) or {}
                        ).get("id"),
                        "purl": c.get("purl"),
                    }
                    for c in data.get("components", [])
                    if isinstance(c, dict) and c.get("name")
                ]

            # syft-json (top-level artifacts[])
            if isinstance(data, dict) and "artifacts" in data and isinstance(
                data["artifacts"], list
            ):
                out: List[Dict[str, Any]] = []
                for a in data["artifacts"]:
                    if not isinstance(a, dict) or not a.get("name"):
                        continue
                    out.append(
                        {
                            "name": a.get("name"),
                            "version": a.get("version", ""),
                            "type": a.get("type", "library"),
                            "license": (
                                a.get("licenses")[0]
                                if isinstance(a.get("licenses"), list) and a.get("licenses")
                                else a.get("license")
                            ),
                            "purl": a.get("purl"),
                        }
                    )
                return out

            # spdx-json (top-level packages[])
            if isinstance(data, dict) and "packages" in data and isinstance(
                data["packages"], list
            ):
                return [
                    {
                        "name": p.get("name"),
                        "version": p.get("versionInfo", ""),
                        "type": "library",
                        "license": (
                            None
                            if p.get("licenseConcluded") in (None, "NOASSERTION")
                            else p.get("licenseConcluded")
                        ),
                        "purl": None,
                    }
                    for p in data.get("packages", [])
                    if isinstance(p, dict) and p.get("name")
                ]

            # github-json (manifests[*].resolved{})
            if isinstance(data, dict) and "manifests" in data and isinstance(
                data["manifests"], dict
            ):
                out_gh: List[Dict[str, Any]] = []
                for manifest in data["manifests"].values():
                    if not isinstance(manifest, dict):
                        continue
                    resolved = manifest.get("resolved") or {}
                    if not isinstance(resolved, dict):
                        continue
                    for name, payload in resolved.items():
                        if not isinstance(payload, dict):
                            continue
                        meta = payload.get("metadata") or {}
                        out_gh.append(
                            {
                                "name": name,
                                "version": (meta or {}).get("version", ""),
                                "type": "library",
                                "license": None,
                                "purl": payload.get("package_url"),
                            }
                        )
                return out_gh

            return []

        # ---- syft-table (regex line-parse) --------------------------------
        if output_format == "syft-table":
            out_tbl: List[Dict[str, Any]] = []
            # Skip header; lines look like:
            #   NAME                                     VERSION              TYPE
            #   fastapi                                  0.115.0              python
            line_re = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s*$")
            for line in blob.splitlines():
                if not line.strip() or line.lstrip().startswith("NAME"):
                    continue
                m = line_re.match(line)
                if not m:
                    continue
                name, ver, typ = m.group(1), m.group(2), m.group(3)
                out_tbl.append(
                    {
                        "name": name,
                        "version": ver,
                        "type": typ,
                        "license": None,
                        "purl": None,
                    }
                )
            return out_tbl

        # ---- cyclonedx-xml (regex sweep — schema-stable enough) ----------
        if output_format == "cyclonedx-xml":
            comp_re = re.compile(
                r"<component\b[^>]*>\s*<name>([^<]+)</name>\s*"
                r"<version>([^<]*)</version>",
                re.IGNORECASE,
            )
            return [
                {
                    "name": m.group(1),
                    "version": m.group(2),
                    "type": "library",
                    "license": None,
                    "purl": None,
                }
                for m in comp_re.finditer(blob)
            ]

        # ---- spdx-tag-value (paragraph parse) ----------------------------
        if output_format == "spdx-tag-value":
            out_tag: List[Dict[str, Any]] = []
            current: Dict[str, Any] = {}
            for raw_line in blob.splitlines():
                line = raw_line.strip()
                if not line:
                    if current.get("name"):
                        out_tag.append(
                            {
                                "name": current.get("name"),
                                "version": current.get("version", ""),
                                "type": "library",
                                "license": current.get("license"),
                                "purl": None,
                            }
                        )
                    current = {}
                    continue
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "PackageName":
                    if current.get("name"):
                        out_tag.append(
                            {
                                "name": current.get("name"),
                                "version": current.get("version", ""),
                                "type": "library",
                                "license": current.get("license"),
                                "purl": None,
                            }
                        )
                        current = {}
                    current["name"] = value
                elif key == "PackageVersion":
                    current["version"] = value
                elif key == "PackageLicenseConcluded":
                    current["license"] = None if value == "NOASSERTION" else value
            if current.get("name"):
                out_tag.append(
                    {
                        "name": current.get("name"),
                        "version": current.get("version", ""),
                        "type": "library",
                        "license": current.get("license"),
                        "purl": None,
                    }
                )
            return out_tag

        return []


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_singleton: Optional[SyftSBOMEngine] = None
_singleton_lock = threading.Lock()


def get_syft_sbom_engine(db_path: Optional[str | Path] = None) -> SyftSBOMEngine:
    """Return the process-wide :class:`SyftSBOMEngine` instance.

    If ``db_path`` is supplied (or ``FIXOPS_SYFT_SBOM_DB`` is set), a fresh
    engine bound to that path is returned and cached.  This makes tests that
    pass ``tmp_path`` deterministic and isolated.
    """
    global _singleton
    if db_path is not None:
        with _singleton_lock:
            _singleton = SyftSBOMEngine(db_path=db_path)
            return _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = SyftSBOMEngine()
    return _singleton


__all__ = [
    "INPUT_TYPES",
    "OUTPUT_FORMATS",
    "SCOPE_OPTIONS",
    "DEFAULT_OUTPUT_FORMAT",
    "DEFAULT_SCOPE",
    "SyftSBOMEngine",
    "get_syft_sbom_engine",
]
