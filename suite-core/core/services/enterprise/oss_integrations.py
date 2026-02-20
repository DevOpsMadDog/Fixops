"""
OSS Toolchain Integrations for FixOps
Implements actual integrations with open source security tools
"""
import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

logger = structlog.get_logger()


class TrivyScanner:
    """Integration with Trivy vulnerability scanner"""

    def __init__(self):
        self.name = "trivy"
        self.version = self._get_version()

    def _get_version(self) -> str:
        try:
            result = subprocess.run(
                ["trivy", "--version"], capture_output=True, text=True
            )
            return (
                result.stdout.split()[1] if result.returncode == 0 else "not-installed"
            )
        except FileNotFoundError:
            return "not-installed"

    async def scan_image(self, image: str) -> Dict[str, Any]:
        """Scan container image for vulnerabilities"""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                output_file = f.name

            cmd = ["trivy", "image", "--format", "json", "--output", output_file, image]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                with open(output_file, "r") as f:
                    results = json.load(f)
                Path(output_file).unlink()  # cleanup
                return {
                    "status": "success",
                    "vulnerabilities": results.get("Results", []),
                    "metadata": results.get("Metadata", {}),
                    "scanner": "trivy",
                }
            else:
                return {"status": "error", "error": stderr.decode(), "scanner": "trivy"}
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
            return {"status": "error", "error": str(e), "scanner": "trivy"}


class OPAPolicyEngine:
    """Integration with Open Policy Agent (OPA)"""

    def __init__(self):
        self.name = "opa"
        self.version = self._get_version()
        self.policies_dir = Path(os.environ.get("FIXOPS_POLICIES_DIR", "data/policies"))
        self.policies_dir.mkdir(parents=True, exist_ok=True)

    def _get_version(self) -> str:
        try:
            result = subprocess.run(["opa", "version"], capture_output=True, text=True)
            return (
                result.stdout.split()[1] if result.returncode == 0 else "not-installed"
            )
        except FileNotFoundError:
            return "not-installed"

    async def evaluate_policy(
        self, policy_name: str, input_data: Dict
    ) -> Dict[str, Any]:
        """Evaluate security policy using OPA"""
        try:
            policy_file = self.policies_dir / f"{policy_name}.rego"
            if not policy_file.exists():
                return {
                    "status": "error",
                    "error": f"Policy {policy_name} not found",
                    "engine": "opa",
                }

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            ) as f:
                json.dump(input_data, f)
                input_file = f.name

            cmd = [
                "opa",
                "eval",
                "--data",
                str(policy_file),
                "--input",
                input_file,
                "--format",
                "json",
                "data.core.allow",
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            Path(input_file).unlink()  # cleanup

            if process.returncode == 0:
                result = json.loads(stdout.decode())
                return {
                    "status": "success",
                    "decision": result.get("result", [{}])[0]
                    .get("expressions", [{}])[0]
                    .get("value", False),
                    "engine": "opa",
                    "policy": policy_name,
                }
            else:
                return {"status": "error", "error": stderr.decode(), "engine": "opa"}
        except Exception as e:
            logger.error(f"OPA policy evaluation failed: {e}")
            return {"status": "error", "error": str(e), "engine": "opa"}


class SigstoreVerifier:
    """Integration with Sigstore for supply chain security"""

    def __init__(self):
        self.name = "cosign"
        self.version = self._get_version()

    def _get_version(self) -> str:
        try:
            result = subprocess.run(
                ["cosign", "version"], capture_output=True, text=True
            )
            return (
                result.stdout.split()[2] if result.returncode == 0 else "not-installed"
            )
        except FileNotFoundError:
            return "not-installed"

    async def verify_signature(
        self, image: str, public_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify container image signatures using cosign"""
        try:
            cmd = ["cosign", "verify", image]
            if public_key:
                cmd.extend(["--key", public_key])

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                return {
                    "status": "success",
                    "verified": True,
                    "signatures": json.loads(stdout.decode()) if stdout else [],
                    "verifier": "sigstore",
                }
            else:
                return {
                    "status": "verified",
                    "verified": False,
                    "error": stderr.decode(),
                    "verifier": "sigstore",
                }
        except Exception as e:
            logger.error(f"Sigstore verification failed: {e}")
            return {"status": "error", "error": str(e), "verifier": "sigstore"}


class GrypeScanner:
    """Integration with Grype vulnerability scanner"""

    def __init__(self):
        self.name = "grype"
        self.version = self._get_version()

    def _get_version(self) -> str:
        try:
            result = subprocess.run(
                ["grype", "version"], capture_output=True, text=True
            )
            return (
                result.stdout.split()[1] if result.returncode == 0 else "not-installed"
            )
        except FileNotFoundError:
            return "not-installed"

    async def scan_target(
        self, target: str, output_format: str = "json"
    ) -> Dict[str, Any]:
        """Scan target for vulnerabilities using Grype"""
        try:
            cmd = ["grype", target, "--output", output_format]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                if output_format == "json":
                    results = json.loads(stdout.decode())
                    return {
                        "status": "success",
                        "vulnerabilities": results.get("matches", []),
                        "metadata": results.get("source", {}),
                        "scanner": "grype",
                    }
                else:
                    return {
                        "status": "success",
                        "output": stdout.decode(),
                        "scanner": "grype",
                    }
            else:
                return {"status": "error", "error": stderr.decode(), "scanner": "grype"}
        except Exception as e:
            logger.error(f"Grype scan failed: {e}")
            return {"status": "error", "error": str(e), "scanner": "grype"}


class OSSIntegrationService:
    """Centralized service for managing OSS tool integrations"""

    def __init__(self):
        self.trivy = TrivyScanner()
        self.opa = OPAPolicyEngine()
        self.sigstore = SigstoreVerifier()
        self.grype = GrypeScanner()

    def get_status(self) -> Dict[str, Any]:
        """Get status of all OSS tools"""
        return {
            "trivy": {
                "name": self.trivy.name,
                "version": self.trivy.version,
                "available": self.trivy.version != "not-installed",
            },
            "opa": {
                "name": self.opa.name,
                "version": self.opa.version,
                "available": self.opa.version != "not-installed",
            },
            "sigstore": {
                "name": self.sigstore.name,
                "version": self.sigstore.version,
                "available": self.sigstore.version != "not-installed",
            },
            "grype": {
                "name": self.grype.name,
                "version": self.grype.version,
                "available": self.grype.version != "not-installed",
            },
        }

    async def comprehensive_scan(
        self, target: str, image_type: bool = True
    ) -> Dict[str, Any]:
        """Run comprehensive security scan using multiple tools"""
        results = {"target": target, "scans": {}}

        # Run Trivy scan for container images
        if image_type and self.trivy.version != "not-installed":
            logger.info(f"Running Trivy scan on {target}")
            results["scans"]["trivy"] = await self.trivy.scan_image(target)

        # Run Grype scan
        if self.grype.version != "not-installed":
            logger.info(f"Running Grype scan on {target}")
            results["scans"]["grype"] = await self.grype.scan_target(target)

        # Verify signatures with Sigstore
        if image_type and self.sigstore.version != "not-installed":
            logger.info(f"Running Sigstore verification on {target}")
            results["scans"]["sigstore"] = await self.sigstore.verify_signature(target)

        return results


# Create default OPA policies
def create_default_policies():
    """Create default security policies for OPA"""
    policies_dir = Path(os.environ.get("FIXOPS_POLICIES_DIR", "data/policies"))
    policies_dir.mkdir(parents=True, exist_ok=True)

    # Basic vulnerability policy
    vuln_policy = """
package fixops

import rego.v1

# Allow if no critical vulnerabilities
allow if {
    count(input.vulnerabilities) == 0
}

allow if {
    count([v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"]) == 0
}

# Allow if critical vulns have patches available
allow if {
    critical_vulns := [v | v := input.vulnerabilities[_]; v.severity == "CRITICAL"]
    count(critical_vulns) > 0
    every vuln in critical_vulns {
        vuln.fix_available == true
    }
}
"""

    (policies_dir / "vulnerability.rego").write_text(vuln_policy)

    # SBOM compliance policy
    sbom_policy = """
package fixops

import rego.v1

# Require SBOM for deployment
allow if {
    input.sbom_present == true
    input.sbom_valid == true
}

# Check for required components
allow if {
    input.sbom_present == true
    required_fields := ["name", "version", "supplier"]
    every field in required_fields {
        input.sbom.metadata[field]
    }
}
"""

    (policies_dir / "sbom.rego").write_text(sbom_policy)


# Initialize on import
create_default_policies()
