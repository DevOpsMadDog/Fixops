"""SOC2 Evidence Bundle Generator — ALDECI.

Compiles quarterly control evidence from live engines into a tamper-evident,
optionally RSA-signed JSON bundle suitable for auditor submission.

SOC2 Trust Service Criteria addressed
--------------------------------------
- CC6.1  Logical access controls        → RBAC role assignments + access changes
- CC6.2  Prior to issuance of passwords → audit log of auth events
- CC7.2  System monitoring              → full audit trail slice
- CC8.1  Change management              → git commit history (release control)
- A1.2   Environmental protections      → backup attestation
- C1.1   Confidentiality                → configuration inventory (names only)
- CC9.2  Vendor risk management         → active vendor list + tier summary

Design principles
-----------------
- Never fabricate: if an engine is unavailable the section is recorded as
  ``{"status": "section_not_available", "reason": "<msg>"}`` rather than
  emitting empty / mock data.
- Engine imports are deferred inside each collector; the class can be
  instantiated in environments where only a subset of engines are installed.
- Signing is purely additive: the original bundle dict is preserved untouched
  inside the sealed envelope.

Usage
-----
    bundler = SOC2EvidenceBundler(db_root=Path("/data/aldeci"))
    bundle  = bundler.collect_quarterly_evidence("2026-Q1", "org_abc")
    sealed  = bundler.seal_bundle(bundle, sign=True)
    bundler.export_bundle(sealed, Path("/tmp/soc2_2026_Q1.json"))
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Quarter helpers
# ---------------------------------------------------------------------------

def _parse_quarter(quarter: str) -> Tuple[datetime, datetime]:
    """Parse a quarter string such as ``2026-Q1`` into (start, end) UTC datetimes.

    Returns inclusive start (first second of the quarter) and exclusive end
    (first second of the following quarter).

    Raises:
        ValueError: If *quarter* is not in ``YYYY-QN`` format or N is not 1-4.
    """
    parts = quarter.upper().split("-Q")
    if len(parts) != 2:
        raise ValueError(f"Quarter must be in YYYY-QN format, got: {quarter!r}")
    try:
        year = int(parts[0])
        qnum = int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Quarter must be in YYYY-QN format, got: {quarter!r}") from exc
    if qnum < 1 or qnum > 4:
        raise ValueError(f"Quarter number must be 1-4, got: {qnum}")
    start_month = (qnum - 1) * 3 + 1
    end_month   = start_month + 3
    start = datetime(year, start_month, 1, tzinfo=timezone.utc)
    if end_month > 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, end_month, 1, tzinfo=timezone.utc)
    return start, end


def _not_available(reason: str) -> Dict[str, str]:
    """Return a standard section-unavailable marker."""
    return {"status": "section_not_available", "reason": reason}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class SOC2EvidenceBundler:
    """Compile and seal quarterly SOC2 control evidence.

    Args:
        db_root: Root directory where ALDECI engine databases live.
                 Individual engines resolve their own DB paths relative to
                 this root (e.g. ``db_root / "audit.db"``).
    """

    def __init__(self, db_root: Path) -> None:
        self.db_root = Path(db_root)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_quarterly_evidence(self, quarter: str, org_id: str) -> Dict[str, Any]:
        """Aggregate evidence from all control domains for one quarter.

        Args:
            quarter: Quarter string in ``YYYY-QN`` format (e.g. ``2026-Q1``).
            org_id:  Tenant / organisation identifier.

        Returns:
            A dict with the following top-level keys:

            ``meta``
                Bundle metadata (quarter, org_id, generated_at, tool_version).
            ``audit_logs``
                Slice of AuditLogger events for the quarter window.
            ``rbac_access_reviews``
                Role assignments and access-change events.
            ``change_history``
                Top-100 git commits within the quarter as release-control evidence.
            ``vendor_risk``
                Active vendor list with risk-tier summary.
            ``incident_timeline``
                Incidents resolved within the quarter.
            ``backup_attestation``
                Latest backup run timestamp (if backup logs are present).
            ``configuration_snapshot``
                Environment variable names (not values) + presence of key
                infrastructure files.

            Any section whose engine is unavailable will contain
            ``{"status": "section_not_available", "reason": "..."}`` rather
            than fabricated data.
        """
        start, end = _parse_quarter(quarter)

        meta: Dict[str, Any] = {
            "quarter":       quarter,
            "org_id":        org_id,
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "tool_version":  "soc2_evidence_bundle_v1",
            "quarter_start": start.isoformat(),
            "quarter_end":   end.isoformat(),
        }

        return {
            "meta":                   meta,
            "audit_logs":             self._collect_audit_logs(org_id, start, end),
            "rbac_access_reviews":    self._collect_rbac(org_id, start, end),
            "change_history":         self._collect_change_history(start, end),
            "vendor_risk":            self._collect_vendor_risk(org_id),
            "incident_timeline":      self._collect_incidents(org_id, start, end),
            "backup_attestation":     self._collect_backup_attestation(),
            "configuration_snapshot": self._collect_configuration_snapshot(),
        }

    def seal_bundle(self, bundle: Dict[str, Any], sign: bool = True) -> Dict[str, Any]:
        """Compute SHA-256 over the canonical bundle JSON; optionally RSA-sign it.

        The canonical form is produced by ``json.dumps`` with
        ``sort_keys=True, separators=(',', ':')``.

        Args:
            bundle: The dict returned by :meth:`collect_quarterly_evidence`.
            sign:   If *True* (default) and :class:`~core.crypto.RSAKeyManager`
                    is available, sign the SHA-256 hash bytes with RSA-4096-SHA256
                    and encode the signature as base64.

        Returns:
            A dict with keys:

            ``bundle``
                The original bundle dict (unmodified).
            ``sha256``
                Hex-encoded SHA-256 digest of the canonical JSON.
            ``signature``
                Base64-encoded RSA signature string, or *None* if signing was
                skipped / unavailable.
            ``signature_fingerprint``
                RSA key fingerprint string, or *None*.
            ``signing_status``
                ``"signed"``, ``"unsigned"`` (sign=False), or
                ``"signing_unavailable:<reason>"``.
            ``signed_at``
                ISO-8601 UTC timestamp of the sealing operation.
        """
        canonical_json: bytes = json.dumps(
            bundle, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")

        sha256_hex: str = hashlib.sha256(canonical_json).hexdigest()

        signature_b64: Optional[str]      = None
        fingerprint:   Optional[str]      = None
        signing_status: str               = "unsigned"
        signed_at: str                    = datetime.now(timezone.utc).isoformat()

        if sign:
            signature_b64, fingerprint, signing_status = self._rsa_sign(sha256_hex.encode("utf-8"))

        return {
            "bundle":                bundle,
            "sha256":                sha256_hex,
            "signature":             signature_b64,
            "signature_fingerprint": fingerprint,
            "signing_status":        signing_status,
            "signed_at":             signed_at,
        }

    def export_bundle(self, sealed: Dict[str, Any], output_path: Path) -> None:
        """Write a sealed bundle to disk as pretty-printed JSON.

        Args:
            sealed:      The dict returned by :meth:`seal_bundle`.
            output_path: Destination file path.  Parent directories are created
                         automatically.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(sealed, fh, indent=2, default=str)
        _logger.info("SOC2 evidence bundle written to %s", output_path)

    # ------------------------------------------------------------------
    # Section collectors (each isolated — failure never propagates)
    # ------------------------------------------------------------------

    def _collect_audit_logs(
        self, org_id: str, start: datetime, end: datetime
    ) -> Dict[str, Any]:
        """Collect AuditLogger events for the quarter window (limit 500)."""
        try:
            from core.audit_logger import AuditLogger  # type: ignore

            db_path = self.db_root / "audit.db"
            logger_inst = AuditLogger(db_path=db_path)
            events = logger_inst.search(
                org_id=org_id,
                since=start,
                until=end,
                limit=500,
            )
            serialised = [e.to_dict() for e in events]
            return {
                "status":      "ok",
                "event_count": len(serialised),
                "events":      serialised,
                "window_start": start.isoformat(),
                "window_end":   end.isoformat(),
            }
        except ImportError as exc:
            return _not_available(f"audit_logger import failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("audit_logs collection error: %s", exc)
            return _not_available(f"collection error: {exc}")

    def _collect_rbac(
        self, org_id: str, start: datetime, end: datetime
    ) -> Dict[str, Any]:
        """Collect RBAC role assignments and access-change events."""
        try:
            from core.audit_logger import AuditLogger  # type: ignore

            db_path = self.db_root / "audit.db"
            logger_inst = AuditLogger(db_path=db_path)

            # Access reviews: role assignments and permission changes
            role_events: List[Any] = []
            for action in ("user.role_assign", "user.role_revoke", "permission.grant", "permission.revoke"):
                role_events.extend(
                    logger_inst.search(
                        org_id=org_id,
                        action=action,
                        since=start,
                        until=end,
                        limit=200,
                    )
                )

            # Deduplicate by event_id
            seen: set = set()
            unique_events: List[Dict[str, Any]] = []
            for ev in role_events:
                if ev.event_id not in seen:
                    seen.add(ev.event_id)
                    unique_events.append(ev.to_dict())

            return {
                "status":              "ok",
                "access_change_count": len(unique_events),
                "access_changes":      unique_events,
                "window_start":        start.isoformat(),
                "window_end":          end.isoformat(),
                "note": (
                    "role_assign / role_revoke / permission.grant / permission.revoke events"
                ),
            }
        except ImportError as exc:
            return _not_available(f"rbac via audit_logger import failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("rbac collection error: %s", exc)
            return _not_available(f"collection error: {exc}")

    def _collect_change_history(
        self, start: datetime, end: datetime
    ) -> Dict[str, Any]:
        """Run ``git log`` for commits within the quarter (top 100)."""
        try:
            after  = start.strftime("%Y-%m-%d")
            before = end.strftime("%Y-%m-%d")
            result = subprocess.run(
                [
                    "git", "log",
                    f"--after={after}",
                    f"--before={before}",
                    "--format=%H|%ae|%ai|%s",
                    "--max-count=100",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(Path(__file__).resolve().parents[2]),
            )
            if result.returncode != 0:
                return _not_available(
                    f"git log exited {result.returncode}: {result.stderr.strip()}"
                )

            commits: List[Dict[str, str]] = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split("|", 3)
                if len(parts) == 4:
                    commits.append({
                        "sha":     parts[0],
                        "author":  parts[1],
                        "date":    parts[2],
                        "subject": parts[3],
                    })

            return {
                "status":       "ok",
                "commit_count": len(commits),
                "commits":      commits,
                "window_start": start.isoformat(),
                "window_end":   end.isoformat(),
                "note":         "git log evidence of release control (max 100 commits)",
            }
        except FileNotFoundError:
            return _not_available("git binary not found")
        except subprocess.TimeoutExpired:
            return _not_available("git log timed out after 15 seconds")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("change_history collection error: %s", exc)
            return _not_available(f"collection error: {exc}")

    def _collect_vendor_risk(self, org_id: str) -> Dict[str, Any]:
        """List active vendors from VendorScorecard with tier summary."""
        try:
            from core.vendor_scorecard import VendorScorecard  # type: ignore

            db_path = self.db_root / "vendor_scorecard.db"
            sc = VendorScorecard(db_path=str(db_path))
            vendors = sc.list_vendors(org_id=org_id)

            tier_summary: Dict[str, int] = {}
            vendor_list: List[Dict[str, Any]] = []
            for v in vendors:
                tier = getattr(v, "tier", None)
                tier_str = tier.value if hasattr(tier, "value") else str(tier or "unknown")
                tier_summary[tier_str] = tier_summary.get(tier_str, 0) + 1
                vendor_list.append({
                    "id":     getattr(v, "id",     None),
                    "name":   getattr(v, "name",   None),
                    "domain": getattr(v, "domain", None),
                    "tier":   tier_str,
                })

            return {
                "status":       "ok",
                "vendor_count": len(vendor_list),
                "tier_summary": tier_summary,
                "vendors":      vendor_list,
            }
        except ImportError as exc:
            return _not_available(f"vendor_scorecard import failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("vendor_risk collection error: %s", exc)
            return _not_available(f"collection error: {exc}")

    def _collect_incidents(
        self, org_id: str, start: datetime, end: datetime
    ) -> Dict[str, Any]:
        """List incidents resolved within the quarter."""
        try:
            from core.incident_timeline_engine import IncidentTimelineEngine  # type: ignore

            db_path = self.db_root / "incident_timeline.db"
            engine  = IncidentTimelineEngine(db_path=str(db_path))
            timelines = engine.list_timelines(org_id=org_id, status="resolved")

            # Filter to those resolved within the quarter window
            in_quarter: List[Dict[str, Any]] = []
            for tl in timelines:
                resolved_at_raw = tl.get("resolved_at")
                if resolved_at_raw:
                    try:
                        if isinstance(resolved_at_raw, str):
                            resolved_at = datetime.fromisoformat(resolved_at_raw)
                            if resolved_at.tzinfo is None:
                                resolved_at = resolved_at.replace(tzinfo=timezone.utc)
                        else:
                            resolved_at = resolved_at_raw
                        if start <= resolved_at < end:
                            in_quarter.append(tl)
                    except (ValueError, TypeError):
                        pass

            return {
                "status":               "ok",
                "resolved_count":       len(in_quarter),
                "incidents":            in_quarter,
                "window_start":         start.isoformat(),
                "window_end":           end.isoformat(),
            }
        except ImportError as exc:
            return _not_available(f"incident_timeline_engine import failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            _logger.warning("incidents collection error: %s", exc)
            return _not_available(f"collection error: {exc}")

    def _collect_backup_attestation(self) -> Dict[str, Any]:
        """Report latest backup run timestamp from backup log files."""
        # Candidate log paths — checked in order; first hit wins.
        candidates: List[Path] = [
            self.db_root / "backup.log",
            self.db_root / "logs" / "backup.log",
            Path(__file__).resolve().parents[2] / "logs" / "backup.log",
            Path(__file__).resolve().parents[2] / "backup.log",
        ]
        for log_path in candidates:
            if log_path.exists():
                try:
                    stat = log_path.stat()
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                    # Read last non-empty line as the most recent log entry
                    last_line: Optional[str] = None
                    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            stripped = line.strip()
                            if stripped:
                                last_line = stripped
                    return {
                        "status":            "ok",
                        "log_path":          str(log_path),
                        "last_modified_utc": mtime,
                        "last_log_entry":    last_line,
                    }
                except Exception as exc:  # noqa: BLE001
                    _logger.warning("backup_attestation read error: %s", exc)
                    return _not_available(f"backup log read error: {exc}")

        return _not_available(
            "no backup.log found in db_root or project root; "
            "run backup.sh and ensure it appends to a known log path"
        )

    def _collect_configuration_snapshot(self) -> Dict[str, Any]:
        """Inventory environment variable names (not values) and key infra files."""
        env_var_names = sorted(os.environ.keys())

        repo_root  = Path(__file__).resolve().parents[2]
        infra_files: Dict[str, bool] = {
            "fly.toml":      (repo_root / "fly.toml").exists(),
            "Dockerfile":    (repo_root / "Dockerfile").exists(),
            "docker-compose.yml": (repo_root / "docker-compose.yml").exists(),
            "docker-compose.yaml": (repo_root / "docker-compose.yaml").exists(),
            ".env.example":  (repo_root / ".env.example").exists(),
            "requirements.txt": (repo_root / "requirements.txt").exists(),
        }

        return {
            "status":           "ok",
            "env_var_count":    len(env_var_names),
            "env_var_names":    env_var_names,
            "note":             "Environment variable names only — values intentionally omitted",
            "infra_files":      infra_files,
            "snapshot_taken_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Signing helper
    # ------------------------------------------------------------------

    def _rsa_sign(
        self, data: bytes
    ) -> Tuple[Optional[str], Optional[str], str]:
        """Attempt RSA signing; return (b64_sig, fingerprint, status_string).

        Returns ``(None, None, "signing_unavailable:<reason>")`` on any
        failure rather than raising.
        """
        try:
            from core.crypto import RSAKeyManager, RSASigner  # type: ignore

            km     = RSAKeyManager()
            signer = RSASigner(key_manager=km)
            sig_bytes, fingerprint = signer.sign(data)
            sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")
            return sig_b64, fingerprint, "signed"
        except ImportError as exc:
            return None, None, f"signing_unavailable:import_error:{exc}"
        except Exception as exc:  # noqa: BLE001
            _logger.warning("RSA signing failed: %s", exc)
            return None, None, f"signing_unavailable:{exc}"
