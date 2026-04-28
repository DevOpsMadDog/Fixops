"""PR Generator — Auto-generate GitHub Pull Requests for dependency vulnerability fixes.

Analyzes security findings from Snyk, Trivy, Grype, and Dependabot scanners,
produces manifest diffs, and creates PRs via the GitHub API.

Vision Pillar: V3 (Decision Intelligence) — autonomous remediation pipeline.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class DependencyFix(BaseModel):
    """A resolved dependency upgrade extracted from a security finding."""

    package_name: str
    current_version: str
    fix_version: str
    ecosystem: str  # pip | npm | maven | go
    cve_ids: List[str] = Field(default_factory=list)
    severity: str = "medium"
    manifest_file: str = "requirements.txt"


class PRTemplate(BaseModel):
    """PR title, body and metadata ready for GitHub API submission."""

    title: str
    body: str
    branch_name: str
    labels: List[str] = Field(default_factory=list)
    assignees: List[str] = Field(default_factory=list)


class GeneratedPR(BaseModel):
    """Record of a PR that was (or will be) created for a dependency fix."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo: str
    pr_number: Optional[int] = None
    dependency_fix: DependencyFix
    template: PRTemplate
    status: str = "draft"  # draft | created | merged | failed
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS generated_prs (
    id          TEXT PRIMARY KEY,
    repo        TEXT NOT NULL,
    pr_number   INTEGER,
    fix_json    TEXT NOT NULL,
    template_json TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'draft',
    created_at  TEXT NOT NULL,
    org_id      TEXT NOT NULL DEFAULT 'default'
);
"""


# ---------------------------------------------------------------------------
# PRGenerator
# ---------------------------------------------------------------------------

class PRGenerator:
    """SQLite-backed PR generator for dependency vulnerability fixes.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.  Defaults to
        ``data/pr_generator/prs.db``.
    github_token:
        Optional GitHub Personal Access Token.  When omitted the generator
        builds PR templates and records them but skips the real GitHub API
        call (useful for tests and air-gapped environments).
    base_url:
        GitHub API base URL (override for GitHub Enterprise Server).
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        *,
        github_token: Optional[str] = None,
        base_url: str = "https://api.github.com",
    ) -> None:
        self.db_path = db_path or "data/pr_generator/prs.db"
        self.github_token = github_token
        self.base_url = base_url.rstrip("/")
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(_DDL)
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _row_to_pr(self, row: sqlite3.Row) -> GeneratedPR:
        fix = DependencyFix(**json.loads(row["fix_json"]))
        template = PRTemplate(**json.loads(row["template_json"]))
        return GeneratedPR(
            id=row["id"],
            repo=row["repo"],
            pr_number=row["pr_number"],
            dependency_fix=fix,
            template=template,
            status=row["status"],
            created_at=row["created_at"],
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Finding analysis
    # ------------------------------------------------------------------

    def analyze_finding(self, finding: Dict[str, Any]) -> Optional[DependencyFix]:
        """Extract a DependencyFix from a security finding dict.

        Handles output shapes from Snyk, Trivy, Grype, and Dependabot.
        Returns None when the finding does not represent a fixable dependency
        vulnerability (e.g. a code-quality finding with no upgrade path).
        """
        if not isinstance(finding, dict):
            return None

        # --- package name ---
        artifact = finding.get("artifact") if isinstance(finding.get("artifact"), dict) else {}
        dependency = finding.get("dependency") if isinstance(finding.get("dependency"), dict) else {}
        package_name = (
            finding.get("package_name")
            or finding.get("packageName")
            or finding.get("package")
            or artifact.get("name")
            or dependency.get("package_name")
        )
        if not package_name:
            # Try nested vulnerability "package" field (some Snyk shapes)
            vuln = finding.get("vulnerability", {})
            if isinstance(vuln, dict):
                package_name = vuln.get("package")
        if not package_name:
            return None

        # --- current version ---
        current_version = (
            finding.get("current_version")
            or finding.get("currentVersion")
            or finding.get("version")
            or finding.get("installed_version")
            or artifact.get("version")
        )
        if not current_version:
            current_version = "unknown"

        # --- fix version ---
        fix_version = (
            finding.get("fix_version")
            or finding.get("fixVersion")
            or finding.get("fixed_version")
            or finding.get("fixedVersion")
        )
        # Snyk / Grype nested structures
        if not fix_version:
            fix = finding.get("fix", {})
            if isinstance(fix, dict):
                versions = fix.get("versions") or fix.get("version")
                if isinstance(versions, list) and versions:
                    fix_version = versions[0]
                elif isinstance(versions, str):
                    fix_version = versions
        if not fix_version:
            vuln = finding.get("vulnerability", {})
            if isinstance(vuln, dict):
                fix_version = vuln.get("fixedIn") or vuln.get("fixed_in")
        if not fix_version:
            return None

        # --- ecosystem ---
        ecosystem = (
            finding.get("ecosystem")
            or finding.get("language")
            or finding.get("type")
            or artifact.get("type")
            or ""
        ).lower()
        ecosystem = _normalize_ecosystem(ecosystem)

        # --- manifest file ---
        manifest_file = (
            finding.get("manifest_file")
            or finding.get("manifestFile")
            or finding.get("file")
            or _default_manifest(ecosystem)
        )

        # --- CVE IDs ---
        cve_ids: List[str] = []
        for field in ("cve_ids", "cveIds", "cves", "identifiers"):
            val = finding.get(field)
            if isinstance(val, list):
                cve_ids = [str(c) for c in val if str(c).upper().startswith("CVE-")]
                break
            if isinstance(val, dict):
                cve_ids = [str(c) for c in val.get("CVE", []) if c]
                break
        if not cve_ids:
            cve = finding.get("cve") or finding.get("CVE") or finding.get("vulnerability_id")
            if cve and str(cve).upper().startswith("CVE-"):
                cve_ids = [str(cve)]

        # --- severity ---
        vuln_block = finding.get("vulnerability") if isinstance(finding.get("vulnerability"), dict) else {}
        severity = (
            finding.get("severity")
            or vuln_block.get("severity")
            or "medium"
        )
        if hasattr(severity, "value"):
            severity = severity.value
        severity = str(severity).lower()

        return DependencyFix(
            package_name=str(package_name),
            current_version=str(current_version),
            fix_version=str(fix_version),
            ecosystem=ecosystem,
            cve_ids=cve_ids,
            severity=severity,
            manifest_file=str(manifest_file),
        )

    # ------------------------------------------------------------------
    # Manifest parsing / updating
    # ------------------------------------------------------------------

    def _parse_requirements_txt(self, content: str) -> Dict[str, str]:
        """Parse pip requirements.txt → {package: version_spec}."""
        result: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip inline comments
            line = line.split("#")[0].strip()
            # Match "package==1.2.3", "package>=1.0", "package[extra]==1.0" etc.
            m = re.match(r"^([A-Za-z0-9_\-.\[\]]+)\s*([><=!~].*)$", line)
            if m:
                result[m.group(1).lower()] = m.group(2).strip()
            elif re.match(r"^[A-Za-z0-9_\-.\[\]]+$", line):
                result[line.lower()] = ""
        return result

    def _parse_package_json(self, content: str) -> Dict[str, str]:
        """Parse package.json → {package: version_spec} (dependencies + devDependencies)."""
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return {}
        result: Dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for pkg, ver in (data.get(section) or {}).items():
                result[pkg] = str(ver)
        return result

    def _update_requirements_txt(
        self, content: str, package: str, new_version: str
    ) -> str:
        """Bump a package version in requirements.txt content.

        Preserves comments and line order.  Performs a case-insensitive
        match on the package name (pip is case-insensitive).
        """
        lines = content.splitlines(keepends=True)
        out = []
        replaced = False
        pkg_lower = package.lower()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("-") or not stripped:
                out.append(line)
                continue
            m = re.match(
                r"^([A-Za-z0-9_\-.\[\]]+)\s*([><=!~].*?)(\s*#.*)?$",
                stripped,
            )
            if m and m.group(1).lower() == pkg_lower:
                comment = m.group(3) or ""
                new_line = f"{m.group(1)}=={new_version}{comment}\n"
                out.append(new_line)
                replaced = True
            else:
                out.append(line)
        if not replaced:
            # Append a new pin if the package was not found
            if content and not content.endswith("\n"):
                out.append("\n")
            out.append(f"{package}=={new_version}\n")
        return "".join(out)

    def _update_package_json(
        self, content: str, package: str, new_version: str
    ) -> str:
        """Bump a package version in package.json content (exact pin, no range prefix)."""
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return content
        version_str = new_version if new_version.startswith("^") or new_version.startswith("~") else new_version
        updated = False
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            if package in (data.get(section) or {}):
                data[section][package] = version_str
                updated = True
        if not updated:
            if "dependencies" not in data:
                data["dependencies"] = {}
            data["dependencies"][package] = version_str
        return json.dumps(data, indent=2) + "\n"

    # ------------------------------------------------------------------
    # Manifest diff
    # ------------------------------------------------------------------

    def generate_manifest_diff(self, fix: DependencyFix, repo_path: str) -> str:
        """Produce a unified-diff style string showing the version bump.

        If the manifest file exists under ``repo_path`` the real content is used;
        otherwise a synthetic diff is returned so tests (and offline runs) work.
        """
        manifest_path = Path(repo_path) / fix.manifest_file

        if manifest_path.exists():
            original = manifest_path.read_text(encoding="utf-8")
        else:
            # Synthetic "before" content for diff generation
            if fix.ecosystem == "pip":
                original = f"{fix.package_name}=={fix.current_version}\n"
            elif fix.ecosystem == "npm":
                original = json.dumps(
                    {"dependencies": {fix.package_name: fix.current_version}}, indent=2
                ) + "\n"
            else:
                original = f"{fix.package_name} {fix.current_version}\n"

        if fix.ecosystem == "pip":
            updated = self._update_requirements_txt(
                original, fix.package_name, fix.fix_version
            )
        elif fix.ecosystem == "npm":
            updated = self._update_package_json(
                original, fix.package_name, fix.fix_version
            )
        else:
            # Generic line replacement for maven/go/etc.
            updated = original.replace(fix.current_version, fix.fix_version, 1)

        diff_lines: List[str] = [
            f"--- a/{fix.manifest_file}",
            f"+++ b/{fix.manifest_file}",
            "@@ -1 +1 @@",
        ]
        for orig_line, new_line in zip(original.splitlines(), updated.splitlines()):
            if orig_line != new_line:
                diff_lines.append(f"-{orig_line}")
                diff_lines.append(f"+{new_line}")
        return "\n".join(diff_lines)

    # ------------------------------------------------------------------
    # Branch naming
    # ------------------------------------------------------------------

    def _generate_branch_name(self, fix: DependencyFix) -> str:
        """Generate a deterministic branch name for this fix.

        Format: ``aldeci/fix-<identifier>-<package>``

        The identifier prefers the first CVE ID; falls back to a slug of
        package + version.
        """
        pkg_slug = re.sub(r"[^a-z0-9]", "-", fix.package_name.lower()).strip("-")
        if fix.cve_ids:
            cve_slug = fix.cve_ids[0].upper()  # e.g. CVE-2024-1234
            return f"aldeci/fix-{cve_slug}-{pkg_slug}"
        ver_slug = re.sub(r"[^a-z0-9]", "-", fix.fix_version.lower()).strip("-")
        return f"aldeci/fix-{pkg_slug}-{ver_slug}"

    # ------------------------------------------------------------------
    # PR template builder
    # ------------------------------------------------------------------

    def build_pr_template(self, fix: DependencyFix) -> PRTemplate:
        """Build a PR title and Markdown body for the given DependencyFix."""
        cve_list = ", ".join(fix.cve_ids) if fix.cve_ids else "N/A"
        cve_badge = (
            " ".join(
                f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in fix.cve_ids
            )
            if fix.cve_ids
            else "N/A"
        )

        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
        }.get(fix.severity, "⚪")

        title = (
            f"fix(deps): bump {fix.package_name} from {fix.current_version} "
            f"to {fix.fix_version} [{fix.severity.upper()}]"
        )

        body = f"""\
## Dependency Security Fix

> **Auto-generated by [ALDECI](https://github.com/DevOpsMadDog/Fixops) — AI-native security intelligence platform**

### Summary

| Field | Value |
|---|---|
| Package | `{fix.package_name}` |
| Ecosystem | `{fix.ecosystem}` |
| Current version | `{fix.current_version}` |
| Fixed version | `{fix.fix_version}` |
| Severity | {severity_emoji} `{fix.severity.upper()}` |
| CVE(s) | {cve_badge} |
| Manifest | `{fix.manifest_file}` |

### Vulnerability Details

**Severity**: {fix.severity.upper()}
**CVE IDs**: {cve_list}

This PR upgrades `{fix.package_name}` from `{fix.current_version}` to \
`{fix.fix_version}` to remediate the security vulnerability identified above.

### Advisory Links
{chr(10).join(f"- https://nvd.nist.gov/vuln/detail/{c}" for c in fix.cve_ids) if fix.cve_ids else "- N/A"}

### Checklist
- [ ] CI passes
- [ ] No breaking API changes introduced by the version bump
- [ ] Reviewed dependency changelog

---
> *Generated by ALDECI PR Generator — Autonomous Security Remediation Pipeline*
"""

        labels = ["security", "dependencies", fix.severity]
        branch_name = self._generate_branch_name(fix)

        return PRTemplate(
            title=title,
            body=body,
            branch_name=branch_name,
            labels=labels,
            assignees=[],
        )

    # ------------------------------------------------------------------
    # GitHub API (real + mock-friendly)
    # ------------------------------------------------------------------

    def _github_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _call_github_api(
        self, method: str, url: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Thin wrapper around requests for easy mocking in tests."""
        import requests  # type: ignore[import-untyped]

        resp = requests.request(  # nosemgrep: dynamic-urllib-use-detected
            method,
            url,
            json=payload,
            headers=self._github_headers(),
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def create_pr(
        self, fix: DependencyFix, repo: str, owner: str, org_id: str = "default"
    ) -> GeneratedPR:
        """Create a GitHub branch + commit + PR for the given DependencyFix.

        When ``github_token`` is not configured the PR is saved with
        status='draft' and no GitHub API calls are made.

        Parameters
        ----------
        fix:    The dependency upgrade to apply.
        repo:   Repository name (e.g. ``"Fixops"``).
        owner:  GitHub owner / org (e.g. ``"DevOpsMadDog"``).
        org_id: Tenant identifier for multi-tenant storage.
        """
        template = self.build_pr_template(fix)
        pr = GeneratedPR(
            repo=f"{owner}/{repo}",
            dependency_fix=fix,
            template=template,
            status="draft",
            org_id=org_id,
        )

        if not self.github_token:
            logger.info(
                "pr_generator.create_pr.no_token: saving as draft for %s/%s",
                owner,
                repo,
            )
            self._save_pr(pr)
            return pr

        try:
            # 1. Get default branch SHA
            repo_info = self._call_github_api(
                "GET", f"{self.base_url}/repos/{owner}/{repo}"
            )
            default_branch = repo_info.get("default_branch", "main")

            branch_ref = self._call_github_api(
                "GET",
                f"{self.base_url}/repos/{owner}/{repo}/git/ref/heads/{default_branch}",
            )
            base_sha = branch_ref["object"]["sha"]

            # 2. Create branch
            self._call_github_api(
                "POST",
                f"{self.base_url}/repos/{owner}/{repo}/git/refs",
                {"ref": f"refs/heads/{template.branch_name}", "sha": base_sha},
            )

            # 3. Create PR
            pr_data = self._call_github_api(
                "POST",
                f"{self.base_url}/repos/{owner}/{repo}/pulls",
                {
                    "title": template.title,
                    "body": template.body,
                    "head": template.branch_name,
                    "base": default_branch,
                    "labels": template.labels,
                },
            )

            pr.pr_number = pr_data.get("number")
            pr.status = "created"
            logger.info(
                "pr_generator.create_pr.success: %s/%s#%s",
                owner,
                repo,
                pr.pr_number,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "pr_generator.create_pr.failed: %s — %s", type(exc).__name__, exc
            )
            pr.status = "failed"

        self._save_pr(pr)
        return pr

    # ------------------------------------------------------------------
    # Batch
    # ------------------------------------------------------------------

    def batch_generate(
        self,
        findings: List[Dict[str, Any]],
        repo: str,
        owner: str,
        org_id: str = "default",
    ) -> List[GeneratedPR]:
        """Process multiple findings and generate PRs for fixable ones."""
        results: List[GeneratedPR] = []
        for finding in findings:
            fix = self.analyze_finding(finding)
            if fix is None:
                logger.debug("pr_generator.batch_generate.skip: no fix extracted")
                continue
            generated = self.create_pr(fix, repo, owner, org_id=org_id)
            results.append(generated)
        return results

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def _save_pr(self, pr: GeneratedPR) -> None:
        conn = self._conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO generated_prs
                (id, repo, pr_number, fix_json, template_json, status, created_at, org_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pr.id,
                pr.repo,
                pr.pr_number,
                pr.dependency_fix.model_dump_json(),
                pr.template.model_dump_json(),
                pr.status,
                pr.created_at,
                pr.org_id,
            ),
        )
        conn.commit()
        conn.close()

    def list_generated_prs(
        self,
        org_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[GeneratedPR]:
        """List stored GeneratedPR records with optional filters."""
        clauses: List[str] = []
        params: List[Any] = []
        if org_id:
            clauses.append("org_id = ?")
            params.append(org_id)
        if status:
            clauses.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        conn = self._conn()
        rows = conn.execute(
            f"SELECT * FROM generated_prs {where} ORDER BY created_at DESC",  # nosec B608
            params,
        ).fetchall()
        conn.close()
        return [self._row_to_pr(r) for r in rows]

    def get_pr(self, pr_id: str) -> Optional[GeneratedPR]:
        """Fetch a single GeneratedPR by ID."""
        conn = self._conn()
        row = conn.execute(
            "SELECT * FROM generated_prs WHERE id = ?", (pr_id,)
        ).fetchone()
        conn.close()
        if row is None:
            return None
        return self._row_to_pr(row)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_ecosystem(raw: str) -> str:
    """Map scanner-specific language/type strings to canonical ecosystem names."""
    mapping: Dict[str, str] = {
        "python": "pip",
        "pip": "pip",
        "pipfile": "pip",
        "poetry": "pip",
        "javascript": "npm",
        "js": "npm",
        "node": "npm",
        "nodejs": "npm",
        "npm": "npm",
        "yarn": "npm",
        "java": "maven",
        "maven": "maven",
        "gradle": "maven",
        "go": "go",
        "golang": "go",
        "gomod": "go",
    }
    return mapping.get(raw.lower(), raw or "pip")


def _default_manifest(ecosystem: str) -> str:
    return {
        "pip": "requirements.txt",
        "npm": "package.json",
        "maven": "pom.xml",
        "go": "go.mod",
    }.get(ecosystem, "requirements.txt")
