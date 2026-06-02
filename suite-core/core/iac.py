"""Infrastructure-as-code posture evaluation utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Set


def _normalise_tokens(*values: Any) -> Set[str]:
    tokens: Set[str] = set()
    for value in values:
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered:
                tokens.add(lowered)
        elif isinstance(value, Iterable):
            for element in value:
                if isinstance(element, str):
                    lowered = element.strip().lower()
                    if lowered:
                        tokens.add(lowered)
    return tokens


@dataclass
class IACTarget:
    identifier: str
    display_name: str
    match_keywords: Set[str]
    required_artifacts: List[str]
    recommended_controls: List[str]
    environments: Set[str]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "IACTarget":
        identifier = str(payload.get("id") or payload.get("name") or "").strip()
        if not identifier:
            raise ValueError("IaC target requires an identifier")
        display_name = str(
            payload.get("display_name") or payload.get("name") or identifier
        )
        keywords = _normalise_tokens(payload.get("match") or payload.get("keywords"))
        required_artifacts = [
            str(item).strip()
            for item in payload.get("required_artifacts", [])
            if str(item).strip()
        ]
        recommended_controls = [
            str(item).strip()
            for item in payload.get("recommended_controls", [])
            if str(item).strip()
        ]
        environments = _normalise_tokens(payload.get("environments"))
        return cls(
            identifier=identifier,
            display_name=display_name,
            match_keywords=keywords,
            required_artifacts=required_artifacts,
            recommended_controls=recommended_controls,
            environments=environments,
        )


# Built-in IaC technology watchlist. Used when the overlay supplies no
# ``targets`` so IaC posture coverage works out-of-the-box rather than
# returning None (overlay-provided targets still take precedence).
_DEFAULT_IAC_TARGETS: List[Dict[str, Any]] = [
    {
        "id": "terraform",
        "display_name": "Terraform",
        "match": ["terraform", "tf", "hcl"],
        "required_artifacts": ["sbom", "sarif"],
        "recommended_controls": [
            "Static IaC scanning (tfsec/checkov)",
            "Encrypt and lock remote state",
            "Least-privilege provider credentials",
        ],
        "environments": ["aws", "azure", "gcp", "on-prem"],
    },
    {
        "id": "cloudformation",
        "display_name": "AWS CloudFormation",
        "match": ["cloudformation", "cfn"],
        "required_artifacts": ["sarif"],
        "recommended_controls": ["cfn-nag/cfn-lint scanning", "Stack drift detection"],
        "environments": ["aws"],
    },
    {
        "id": "kubernetes",
        "display_name": "Kubernetes",
        "match": ["kubernetes", "k8s", "kubectl", "manifest"],
        "required_artifacts": ["sbom", "sarif"],
        "recommended_controls": [
            "Pod Security Standards",
            "Network policies",
            "Admission control (OPA/Kyverno)",
        ],
        "environments": ["aws", "azure", "gcp", "on-prem"],
    },
    {
        "id": "helm",
        "display_name": "Helm",
        "match": ["helm", "chart"],
        "required_artifacts": ["sbom"],
        "recommended_controls": ["Chart provenance/signing", "Values secret scanning"],
        "environments": ["aws", "azure", "gcp", "on-prem"],
    },
    {
        "id": "ansible",
        "display_name": "Ansible",
        "match": ["ansible", "playbook"],
        "required_artifacts": ["sarif"],
        "recommended_controls": ["ansible-lint", "Vault for secrets"],
        "environments": ["on-prem", "aws", "azure", "gcp"],
    },
    {
        "id": "pulumi",
        "display_name": "Pulumi",
        "match": ["pulumi"],
        "required_artifacts": ["sbom", "sarif"],
        "recommended_controls": ["Policy as code (CrossGuard)", "Encrypted secrets"],
        "environments": ["aws", "azure", "gcp"],
    },
    {
        "id": "bicep",
        "display_name": "Azure Bicep/ARM",
        "match": ["bicep", "arm"],
        "required_artifacts": ["sarif"],
        "recommended_controls": ["Bicep linter", "what-if drift checks"],
        "environments": ["azure"],
    },
    {
        "id": "dockerfile",
        "display_name": "Dockerfile / OCI image",
        "match": ["dockerfile", "docker", "containerfile", "oci"],
        "required_artifacts": ["sbom"],
        "recommended_controls": [
            "hadolint",
            "Non-root runtime user",
            "Minimal/distroless base image",
        ],
        "environments": ["aws", "azure", "gcp", "on-prem"],
    },
]


class IaCPostureEvaluator:
    """Evaluate IaC coverage across multi-cloud and on-prem deployments."""

    def __init__(self, settings: Mapping[str, Any]):
        raw_targets = settings.get("targets") if isinstance(settings, Mapping) else []
        # Fall back to the built-in watchlist when the overlay supplies none.
        if not raw_targets:
            raw_targets = _DEFAULT_IAC_TARGETS
        targets: List[IACTarget] = []
        for entry in raw_targets or []:
            if not isinstance(entry, Mapping):
                continue
            try:
                targets.append(IACTarget.from_mapping(entry))
            except ValueError:
                continue
        self.targets = targets
        self.settings = dict(settings)

    def evaluate(
        self,
        design_rows: List[Mapping[str, Any]],
        crosswalk: List[Mapping[str, Any]],
        pipeline_result: MutableMapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if not self.targets:
            return None

        unmatched_components: Set[str] = set()
        coverage: List[Dict[str, Any]] = []
        for target in self.targets:
            matched_components: List[str] = []
            matched_environments: Set[str] = set()
            for row in design_rows:
                tokens = _normalise_tokens(
                    row.get("component"),
                    row.get("Component"),
                    row.get("service"),
                    row.get("name"),
                    row.get("platform"),
                    row.get("cloud"),
                    row.get("environment"),
                    row.get("deployment"),
                    row.get("iac_module"),
                    row.get("notes"),
                )
                if not tokens:
                    continue
                if target.match_keywords and target.match_keywords.isdisjoint(tokens):
                    continue
                component_name = (
                    str(
                        row.get("component")
                        or row.get("name")
                        or row.get("service")
                        or ""
                    )
                ).strip()
                if component_name:
                    matched_components.append(component_name)
                matched_environments.update(tokens & target.environments)
            if not matched_components:
                coverage.append(
                    {
                        "id": target.identifier,
                        "name": target.display_name,
                        "matched": False,
                        "matched_components": [],
                        "environments_detected": [],
                        "artifacts_missing": target.required_artifacts,
                        "recommended_controls": target.recommended_controls,
                    }
                )
                continue

            artifacts_missing = [
                artifact
                for artifact in target.required_artifacts
                if not pipeline_result.get(artifact)
            ]
            coverage.append(
                {
                    "id": target.identifier,
                    "name": target.display_name,
                    "matched": True,
                    "matched_components": sorted(set(matched_components)),
                    "environments_detected": sorted(matched_environments),
                    "artifacts_missing": artifacts_missing,
                    "recommended_controls": target.recommended_controls,
                }
            )

        for entry in crosswalk:
            design_row = entry.get("design_row")
            if not isinstance(design_row, Mapping):
                continue
            name = (
                str(
                    design_row.get("component")
                    or design_row.get("name")
                    or design_row.get("service")
                    or ""
                )
            ).strip()
            if not name:
                continue
            tokens = _normalise_tokens(
                design_row.get("platform"),
                design_row.get("cloud"),
                design_row.get("environment"),
                design_row.get("deployment"),
                design_row.get("notes"),
            )
            if any(
                not target.match_keywords.isdisjoint(tokens) for target in self.targets
            ):
                continue
            unmatched_components.add(name)

        summary = {
            "targets": coverage,
            "unmatched_components": sorted(unmatched_components),
        }
        return summary


__all__ = ["IaCPostureEvaluator"]
