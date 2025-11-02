"""
EvidenceValidator: Validates evidence bundles for E2E testing.

This component extracts and validates evidence bundles, checking manifest structure,
payload structure, metadata, encryption, compression, and retention settings.
"""

import gzip
import json
import zipfile
from pathlib import Path
from typing import Optional


class EvidenceBundle:
    """Represents an extracted evidence bundle."""

    def __init__(
        self,
        bundle_path: Path,
        manifest: dict,
        payload: dict,
        metadata: Optional[dict] = None,
    ):
        self.bundle_path = bundle_path
        self.manifest = manifest
        self.payload = payload
        self.metadata = metadata or {}

    @property
    def run_id(self) -> str:
        """Get run ID from manifest."""
        return self.manifest.get("run_id", "")

    @property
    def producer(self) -> str:
        """Get producer from payload."""
        return self.payload.get("producer", "")

    @property
    def retention_days(self) -> Optional[int]:
        """Get retention days from metadata."""
        return self.metadata.get("retention_days")

    @property
    def encrypted(self) -> bool:
        """Check if bundle is encrypted."""
        return self.metadata.get("encrypted", False)

    @property
    def compressed(self) -> bool:
        """Check if bundle is compressed."""
        return self.metadata.get("compressed", False)


class EvidenceValidator:
    """Validates evidence bundles for E2E testing."""

    def __init__(self):
        """Initialize EvidenceValidator."""
        pass

    def find_bundles(self, evidence_dir: Path) -> list[Path]:
        """
        Find all evidence bundle files in a directory.

        Args:
            evidence_dir: Directory to search for bundles

        Returns:
            List of bundle file paths
        """
        if not evidence_dir.exists():
            return []

        bundles = []
        for pattern in ["*.zip", "*.json.gz", "*.json"]:
            bundles.extend(evidence_dir.glob(pattern))

        return sorted(bundles)

    def extract_bundle(self, bundle_path: Path) -> EvidenceBundle:
        """
        Extract and parse an evidence bundle.

        Args:
            bundle_path: Path to bundle file

        Returns:
            EvidenceBundle object

        Raises:
            ValueError: If bundle format is invalid
        """
        if not bundle_path.exists():
            raise FileNotFoundError(f"Bundle not found: {bundle_path}")

        if bundle_path.suffix == ".zip":
            return self._extract_zip_bundle(bundle_path)
        elif bundle_path.name.endswith(".json.gz"):
            return self._extract_gzip_bundle(bundle_path)
        elif bundle_path.suffix == ".json":
            return self._extract_json_bundle(bundle_path)
        else:
            raise ValueError(f"Unknown bundle format: {bundle_path}")

    def _extract_zip_bundle(self, bundle_path: Path) -> EvidenceBundle:
        """Extract a ZIP evidence bundle."""
        with zipfile.ZipFile(bundle_path, "r") as zf:
            manifest = None
            payload = None
            metadata = None

            if "manifest.json" in zf.namelist():
                with zf.open("manifest.json") as f:
                    manifest = json.load(f)

            if "payload.json" in zf.namelist():
                with zf.open("payload.json") as f:
                    payload = json.load(f)

            if "metadata.json" in zf.namelist():
                with zf.open("metadata.json") as f:
                    metadata = json.load(f)

            if manifest is None or payload is None:
                raise ValueError(
                    "Bundle missing required files (manifest.json, payload.json)"
                )

            return EvidenceBundle(bundle_path, manifest, payload, metadata)

    def _extract_gzip_bundle(self, bundle_path: Path) -> EvidenceBundle:
        """Extract a gzipped JSON evidence bundle."""
        with gzip.open(bundle_path, "rt") as f:
            data = json.load(f)

        if "manifest" in data and "payload" in data:
            manifest = data.get("manifest", {})
            payload = data.get("payload", {})
            metadata = data.get("metadata", {})
        else:
            payload = data
            manifest = {}
            metadata = {}

            manifest_path = bundle_path.parent / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path, "r") as f:
                    manifest = json.load(f)
                    metadata = {
                        "retention_days": manifest.get("retention_days"),
                        "encrypted": manifest.get("encrypted", False),
                        "compressed": manifest.get("compressed", False),
                    }

        return EvidenceBundle(bundle_path, manifest, payload, metadata)

    def _extract_json_bundle(self, bundle_path: Path) -> EvidenceBundle:
        """Extract a plain JSON evidence bundle."""
        with open(bundle_path, "r") as f:
            data = json.load(f)

        if "manifest" in data and "payload" in data:
            manifest = data.get("manifest", {})
            payload = data.get("payload", {})
            metadata = data.get("metadata", {})
        else:
            payload = data
            manifest = {}
            metadata = {}

            manifest_path = bundle_path.parent / "manifest.json"
            if manifest_path.exists():
                with open(manifest_path, "r") as f:
                    manifest = json.load(f)
                    metadata = {
                        "retention_days": manifest.get("retention_days"),
                        "encrypted": manifest.get("encrypted", False),
                        "compressed": manifest.get("compressed", False),
                    }

        return EvidenceBundle(bundle_path, manifest, payload, metadata)

    def validate_manifest(self, manifest: dict) -> list[str]:
        """
        Validate manifest structure.

        Args:
            manifest: Manifest dict

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        required_fields = ["run_id", "timestamp", "version"]
        for field in required_fields:
            if field not in manifest:
                errors.append(f"Missing required field in manifest: {field}")

        if "run_id" in manifest and not manifest["run_id"]:
            errors.append("run_id is empty")

        return errors

    def validate_payload(self, payload: dict) -> list[str]:
        """
        Validate payload structure.

        Args:
            payload: Payload dict

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        required_fields = ["producer", "run_id"]
        for field in required_fields:
            if field not in payload:
                errors.append(f"Missing required field in payload: {field}")

        return errors

    def validate_bundle(self, bundle: EvidenceBundle) -> list[str]:
        """
        Validate complete evidence bundle.

        Args:
            bundle: EvidenceBundle object

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        errors.extend(self.validate_manifest(bundle.manifest))
        errors.extend(self.validate_payload(bundle.payload))

        return errors

    def check_branding(self, bundle: EvidenceBundle, expected_name: str) -> bool:
        """
        Check if bundle has expected branding.

        Args:
            bundle: EvidenceBundle object
            expected_name: Expected product name

        Returns:
            True if branding matches
        """
        producer = bundle.producer.lower()
        expected = expected_name.lower()
        return expected in producer

    def check_retention(self, bundle: EvidenceBundle, expected_days: int) -> bool:
        """
        Check if bundle has expected retention days.

        Args:
            bundle: EvidenceBundle object
            expected_days: Expected retention days

        Returns:
            True if retention matches
        """
        return bundle.retention_days == expected_days

    def check_encryption(self, bundle: EvidenceBundle, expected: bool) -> bool:
        """
        Check if bundle encryption matches expectation.

        Args:
            bundle: EvidenceBundle object
            expected: Expected encryption state

        Returns:
            True if encryption matches
        """
        return bundle.encrypted == expected

    def check_no_secrets(self, bundle: EvidenceBundle) -> list[str]:
        """
        Check that bundle contains no secrets or PII.

        Args:
            bundle: EvidenceBundle object

        Returns:
            List of potential secret leaks found
        """
        leaks = []

        bundle_str = json.dumps(bundle.payload)

        secret_patterns = [
            ("API key", "api_key"),
            ("API token", "api_token"),
            ("Password", "password"),
            ("Secret", "secret"),
            ("Private key", "private_key"),
            ("Access token", "access_token"),
        ]

        for name, pattern in secret_patterns:
            if pattern in bundle_str.lower():
                leaks.append(f"Potential {name} leak: found '{pattern}' in bundle")

        return leaks
