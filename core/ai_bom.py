"""AI Bill of Materials (AI-BOM) Generator.

This module provides the core logic for generating AI-BOMs in CycloneDX format (v1.5+).
It tracks model provenance, training data lineage, model cards, and usage context.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class ModelCard:
    """Standardized Model Card metadata (ISO/IEC 42001 & NIST AI RMF)."""

    model_id: str
    name: str
    version: str
    author: str
    description: str
    license: str
    framework: str  # pytorch, tensorflow, sklearn, etc.
    model_type: str  # llm, classification, regression, etc.
    tags: List[str] = field(default_factory=list)
    intended_use: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    ethical_considerations: List[str] = field(default_factory=list)
    inputs: List[Dict[str, str]] = field(default_factory=list)
    outputs: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class TrainingData:
    """Metadata about training datasets."""

    name: str
    url: Optional[str] = None
    description: Optional[str] = None
    provenance: str = "unknown"  # public, proprietary, synthetic
    size: str = "unknown"
    license: str = "unknown"
    sensitive_data: bool = False
    pii_present: bool = False
    bias_analysis: Optional[str] = None
    hash_alg: str = "sha256"
    hash_value: Optional[str] = None


@dataclass
class AIBOM:
    """AI Bill of Materials container."""

    bom_format: str = "CycloneDX"
    spec_version: str = "1.5"
    serial_number: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    version: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    components: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> str:
        """Serialize AI-BOM to JSON string."""
        return json.dumps(
            {
                "bomFormat": self.bom_format,
                "specVersion": self.spec_version,
                "serialNumber": self.serial_number,
                "version": self.version,
                "metadata": self.metadata,
                "components": self.components,
                "services": self.services,
                "dependencies": self.dependencies,
            },
            indent=2,
        )


class AIBOMGenerator:
    """Generates AI-BOMs from model and training data metadata."""

    def __init__(self, organization: str = "FixOps"):
        self.organization = organization
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def create_bom(
        self,
        model_card: ModelCard,
        training_data: Optional[List[TrainingData]] = None,
        dependencies: Optional[List[Dict[str, str]]] = None,
    ) -> AIBOM:
        """Create a full AI-BOM."""
        metadata = self._build_metadata(model_card)
        components = self._build_components(model_card, training_data or [], dependencies or [])
        
        return AIBOM(
            metadata=metadata,
            components=components,
        )

    def _build_metadata(self, model: ModelCard) -> Dict[str, Any]:
        """Build BOM metadata section."""
        return {
            "timestamp": self.timestamp,
            "component": {
                "type": "machine-learning-model",
                "name": model.name,
                "version": model.version,
                "group": self.organization,
                "description": model.description,
                "author": model.author,
                "licenses": [{"license": {"id": model.license}}],
                "purl": f"pkg:ml/{self.organization}/{model.name}@{model.version}",
            },
            "tools": [
                {
                    "vendor": "FixOps",
                    "name": "AI-BOM Generator",
                    "version": "1.0.0"
                }
            ],
            "properties": [
                {"name": "fixops:model_type", "value": model.model_type},
                {"name": "fixops:framework", "value": model.framework},
                {"name": "fixops:intended_use", "value": ", ".join(model.intended_use)},
                {"name": "fixops:limitations", "value": ", ".join(model.limitations)},
            ]
        }

    def _build_components(
        self, 
        model: ModelCard, 
        datasets: List[TrainingData], 
        libs: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """Build BOM components (datasets, libraries)."""
        components = []

        # Add Training Data Components
        for data in datasets:
            comp = {
                "type": "data",
                "name": data.name,
                "description": data.description or "Training dataset",
                "scope": "required",
                "properties": [
                    {"name": "fixops:data:provenance", "value": data.provenance},
                    {"name": "fixops:data:size", "value": data.size},
                    {"name": "fixops:data:sensitive", "value": str(data.sensitive_data).lower()},
                    {"name": "fixops:data:pii", "value": str(data.pii_present).lower()},
                ]
            }
            if data.url:
                comp["externalReferences"] = [
                    {"type": "source-distribution", "url": data.url}
                ]
            if data.hash_value:
                comp["hashes"] = [
                    {"alg": data.hash_alg.upper(), "content": data.hash_value}
                ]
            if data.license != "unknown":
                comp["licenses"] = [{"license": {"id": data.license}}]
            
            components.append(comp)

        # Add Library Dependencies (e.g., torch, tensorflow)
        for lib in libs:
            comp = {
                "type": "library",
                "name": lib.get("name", "unknown"),
                "version": lib.get("version", "unknown"),
                "purl": f"pkg:pypi/{lib.get('name')}@{lib.get('version')}"
            }
            components.append(comp)

        return components

    def generate_hash(self, content: Union[str, bytes]) -> str:
        """Helper to generate SHA-256 hash."""
        if isinstance(content, str):
            content = content.encode("utf-8")
        return hashlib.sha256(content).hexdigest()
