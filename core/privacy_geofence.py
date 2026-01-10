"""Privacy Geofencing for EvidenceHub.

This module enforces data residency controls for evidence bundles.
It ensures that data is stored in allowed geographic regions and prevents access
from unauthorized zones, complying with GDPR, CCPA, and other sovereignty laws.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

from core.configuration import OverlayConfig

logger = logging.getLogger(__name__)


class GeoRegion(Enum):
    """Supported geographic regions."""
    US = "us"
    EU = "eu"
    APAC = "apac"
    CN = "cn"
    GLOBAL = "global"


@dataclass
class DataResidencyPolicy:
    """Policy defining allowed storage and access regions."""
    
    allowed_storage_regions: Set[GeoRegion]
    allowed_access_regions: Set[GeoRegion]
    block_cross_border_transfer: bool = True
    # If true, metadata can be global but sensitive payloads must stay in region
    metadata_exception: bool = False


class PrivacyGeofence:
    """Enforces data residency boundaries."""

    def __init__(self, config: OverlayConfig):
        self.config = config
        self.policy = self._load_policy()
        # Mock mapping of storage paths to regions for demonstration
        self.storage_map: Dict[str, GeoRegion] = {
            "s3://fixops-eu-central": GeoRegion.EU,
            "s3://fixops-us-east": GeoRegion.US,
            "s3://fixops-apac-tokyo": GeoRegion.APAC,
            "local": GeoRegion.US,  # Default local to US for this example
        }

    def _load_policy(self) -> DataResidencyPolicy:
        """Load residency policy from overlay config."""
        # Defaults to safe policy: specific region only
        region_str = self.config.flag_provider.string("fixops.compliance.region", "us").lower()
        
        try:
            primary_region = GeoRegion(region_str)
        except ValueError:
            primary_region = GeoRegion.US
            logger.warning(f"Invalid region '{region_str}', defaulting to US")

        return DataResidencyPolicy(
            allowed_storage_regions={primary_region},
            allowed_access_regions={primary_region},
            block_cross_border_transfer=True
        )

    def validate_storage_location(self, path: Path) -> bool:
        """Check if a storage path is allowed by residency policy.
        
        Args:
            path: The file path or URI where data will be stored.
            
        Returns:
            True if allowed, False otherwise.
        """
        # Logic to determine region from path (simplified)
        str_path = str(path)
        detected_region = GeoRegion.US  # Default
        
        if "eu-central" in str_path or "/eu/" in str_path:
            detected_region = GeoRegion.EU
        elif "apac" in str_path or "/apac/" in str_path:
            detected_region = GeoRegion.APAC
            
        if detected_region not in self.policy.allowed_storage_regions:
            logger.error(
                f"Geofence Violation: Attempt to store data in {detected_region.value} "
                f"but policy allows only {self.policy.allowed_storage_regions}"
            )
            return False
            
        return True

    def validate_access_request(self, request_origin_region: str) -> bool:
        """Check if an access request comes from an allowed region.
        
        Args:
            request_origin_region: Region code (e.g., 'eu', 'us') from request context.
            
        Returns:
            True if allowed, False otherwise.
        """
        try:
            origin = GeoRegion(request_origin_region.lower())
        except ValueError:
            logger.warning(f"Unknown access origin: {request_origin_region}")
            return False

        if origin not in self.policy.allowed_access_regions:
            logger.warning(
                f"Geofence Violation: Access denied from {origin.value}. "
                f"Allowed: {self.policy.allowed_access_regions}"
            )
            return False
            
        return True

    def enforce_transfer_block(self, source_region: GeoRegion, dest_region: GeoRegion) -> bool:
        """Check if moving data between regions is allowed."""
        if source_region == dest_region:
            return True
            
        if self.policy.block_cross_border_transfer:
            logger.error(
                f"Geofence Block: Transfer from {source_region.value} to {dest_region.value} blocked."
            )
            return False
            
        return True
