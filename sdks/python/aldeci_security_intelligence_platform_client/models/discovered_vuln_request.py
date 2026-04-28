from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.attack_vector import AttackVector
from ..models.discovery_source import DiscoverySource
from ..models.impact_type import ImpactType
from ..models.vuln_severity import VulnSeverity
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.affected_component import AffectedComponent
    from ..models.vulnerability_evidence import VulnerabilityEvidence


T = TypeVar("T", bound="DiscoveredVulnRequest")


@_attrs_define
class DiscoveredVulnRequest:
    """Request to report a discovered vulnerability.

    Most fields are optional with sensible defaults to support both quick
    reporting from the UI and detailed researcher submissions.

        Attributes:
            title (str | Unset):  Default: 'Untitled Vulnerability'.
            description (str | Unset):  Default: 'Vulnerability discovered via ALdeci platform.'.
            severity (VulnSeverity | Unset): Vulnerability severity levels.
            impact_type (ImpactType | Unset): Impact types.
            attack_vector (AttackVector | Unset): Attack vectors.
            discovery_source (DiscoverySource | Unset): How the vulnerability was discovered.
            discovered_by (str | Unset): Researcher/team name Default: 'ALdeci Platform'.
            discovered_date (datetime.datetime | None | Unset):
            affected_components (list[AffectedComponent] | Unset):
            affected_versions (str | Unset): e.g., '< 2.1.5' or '1.0.0 - 2.0.0' Default: 'unknown'.
            proof_of_concept (None | str | Unset): PoC code or steps
            exploitation_difficulty (str | Unset): trivial, low, medium, high Default: 'medium'.
            cvss_vector (None | str | Unset): CVSS 3.1 vector string
            cvss_score (float | None | Unset):
            remediation (None | str | Unset):
            workaround (None | str | Unset):
            evidence (list[VulnerabilityEvidence] | Unset):
            internal_only (bool | Unset): Keep internal, don't publish Default: True.
            notify_vendor (bool | Unset):  Default: False.
            references (list[str] | Unset):
            tags (list[str] | Unset):
    """

    title: str | Unset = "Untitled Vulnerability"
    description: str | Unset = "Vulnerability discovered via ALdeci platform."
    severity: VulnSeverity | Unset = UNSET
    impact_type: ImpactType | Unset = UNSET
    attack_vector: AttackVector | Unset = UNSET
    discovery_source: DiscoverySource | Unset = UNSET
    discovered_by: str | Unset = "ALdeci Platform"
    discovered_date: datetime.datetime | None | Unset = UNSET
    affected_components: list[AffectedComponent] | Unset = UNSET
    affected_versions: str | Unset = "unknown"
    proof_of_concept: None | str | Unset = UNSET
    exploitation_difficulty: str | Unset = "medium"
    cvss_vector: None | str | Unset = UNSET
    cvss_score: float | None | Unset = UNSET
    remediation: None | str | Unset = UNSET
    workaround: None | str | Unset = UNSET
    evidence: list[VulnerabilityEvidence] | Unset = UNSET
    internal_only: bool | Unset = True
    notify_vendor: bool | Unset = False
    references: list[str] | Unset = UNSET
    tags: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        severity: str | Unset = UNSET
        if not isinstance(self.severity, Unset):
            severity = self.severity.value

        impact_type: str | Unset = UNSET
        if not isinstance(self.impact_type, Unset):
            impact_type = self.impact_type.value

        attack_vector: str | Unset = UNSET
        if not isinstance(self.attack_vector, Unset):
            attack_vector = self.attack_vector.value

        discovery_source: str | Unset = UNSET
        if not isinstance(self.discovery_source, Unset):
            discovery_source = self.discovery_source.value

        discovered_by = self.discovered_by

        discovered_date: None | str | Unset
        if isinstance(self.discovered_date, Unset):
            discovered_date = UNSET
        elif isinstance(self.discovered_date, datetime.datetime):
            discovered_date = self.discovered_date.isoformat()
        else:
            discovered_date = self.discovered_date

        affected_components: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.affected_components, Unset):
            affected_components = []
            for affected_components_item_data in self.affected_components:
                affected_components_item = affected_components_item_data.to_dict()
                affected_components.append(affected_components_item)

        affected_versions = self.affected_versions

        proof_of_concept: None | str | Unset
        if isinstance(self.proof_of_concept, Unset):
            proof_of_concept = UNSET
        else:
            proof_of_concept = self.proof_of_concept

        exploitation_difficulty = self.exploitation_difficulty

        cvss_vector: None | str | Unset
        if isinstance(self.cvss_vector, Unset):
            cvss_vector = UNSET
        else:
            cvss_vector = self.cvss_vector

        cvss_score: float | None | Unset
        if isinstance(self.cvss_score, Unset):
            cvss_score = UNSET
        else:
            cvss_score = self.cvss_score

        remediation: None | str | Unset
        if isinstance(self.remediation, Unset):
            remediation = UNSET
        else:
            remediation = self.remediation

        workaround: None | str | Unset
        if isinstance(self.workaround, Unset):
            workaround = UNSET
        else:
            workaround = self.workaround

        evidence: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.evidence, Unset):
            evidence = []
            for evidence_item_data in self.evidence:
                evidence_item = evidence_item_data.to_dict()
                evidence.append(evidence_item)

        internal_only = self.internal_only

        notify_vendor = self.notify_vendor

        references: list[str] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = self.references

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if impact_type is not UNSET:
            field_dict["impact_type"] = impact_type
        if attack_vector is not UNSET:
            field_dict["attack_vector"] = attack_vector
        if discovery_source is not UNSET:
            field_dict["discovery_source"] = discovery_source
        if discovered_by is not UNSET:
            field_dict["discovered_by"] = discovered_by
        if discovered_date is not UNSET:
            field_dict["discovered_date"] = discovered_date
        if affected_components is not UNSET:
            field_dict["affected_components"] = affected_components
        if affected_versions is not UNSET:
            field_dict["affected_versions"] = affected_versions
        if proof_of_concept is not UNSET:
            field_dict["proof_of_concept"] = proof_of_concept
        if exploitation_difficulty is not UNSET:
            field_dict["exploitation_difficulty"] = exploitation_difficulty
        if cvss_vector is not UNSET:
            field_dict["cvss_vector"] = cvss_vector
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if workaround is not UNSET:
            field_dict["workaround"] = workaround
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if internal_only is not UNSET:
            field_dict["internal_only"] = internal_only
        if notify_vendor is not UNSET:
            field_dict["notify_vendor"] = notify_vendor
        if references is not UNSET:
            field_dict["references"] = references
        if tags is not UNSET:
            field_dict["tags"] = tags

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.affected_component import AffectedComponent
        from ..models.vulnerability_evidence import VulnerabilityEvidence

        d = dict(src_dict)
        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        _severity = d.pop("severity", UNSET)
        severity: VulnSeverity | Unset
        if isinstance(_severity, Unset):
            severity = UNSET
        else:
            severity = VulnSeverity(_severity)

        _impact_type = d.pop("impact_type", UNSET)
        impact_type: ImpactType | Unset
        if isinstance(_impact_type, Unset):
            impact_type = UNSET
        else:
            impact_type = ImpactType(_impact_type)

        _attack_vector = d.pop("attack_vector", UNSET)
        attack_vector: AttackVector | Unset
        if isinstance(_attack_vector, Unset):
            attack_vector = UNSET
        else:
            attack_vector = AttackVector(_attack_vector)

        _discovery_source = d.pop("discovery_source", UNSET)
        discovery_source: DiscoverySource | Unset
        if isinstance(_discovery_source, Unset):
            discovery_source = UNSET
        else:
            discovery_source = DiscoverySource(_discovery_source)

        discovered_by = d.pop("discovered_by", UNSET)

        def _parse_discovered_date(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                discovered_date_type_0 = isoparse(data)

                return discovered_date_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        discovered_date = _parse_discovered_date(d.pop("discovered_date", UNSET))

        _affected_components = d.pop("affected_components", UNSET)
        affected_components: list[AffectedComponent] | Unset = UNSET
        if _affected_components is not UNSET:
            affected_components = []
            for affected_components_item_data in _affected_components:
                affected_components_item = AffectedComponent.from_dict(affected_components_item_data)

                affected_components.append(affected_components_item)

        affected_versions = d.pop("affected_versions", UNSET)

        def _parse_proof_of_concept(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        proof_of_concept = _parse_proof_of_concept(d.pop("proof_of_concept", UNSET))

        exploitation_difficulty = d.pop("exploitation_difficulty", UNSET)

        def _parse_cvss_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cvss_vector = _parse_cvss_vector(d.pop("cvss_vector", UNSET))

        def _parse_cvss_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        cvss_score = _parse_cvss_score(d.pop("cvss_score", UNSET))

        def _parse_remediation(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation = _parse_remediation(d.pop("remediation", UNSET))

        def _parse_workaround(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        workaround = _parse_workaround(d.pop("workaround", UNSET))

        _evidence = d.pop("evidence", UNSET)
        evidence: list[VulnerabilityEvidence] | Unset = UNSET
        if _evidence is not UNSET:
            evidence = []
            for evidence_item_data in _evidence:
                evidence_item = VulnerabilityEvidence.from_dict(evidence_item_data)

                evidence.append(evidence_item)

        internal_only = d.pop("internal_only", UNSET)

        notify_vendor = d.pop("notify_vendor", UNSET)

        references = cast(list[str], d.pop("references", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        discovered_vuln_request = cls(
            title=title,
            description=description,
            severity=severity,
            impact_type=impact_type,
            attack_vector=attack_vector,
            discovery_source=discovery_source,
            discovered_by=discovered_by,
            discovered_date=discovered_date,
            affected_components=affected_components,
            affected_versions=affected_versions,
            proof_of_concept=proof_of_concept,
            exploitation_difficulty=exploitation_difficulty,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            remediation=remediation,
            workaround=workaround,
            evidence=evidence,
            internal_only=internal_only,
            notify_vendor=notify_vendor,
            references=references,
            tags=tags,
        )

        discovered_vuln_request.additional_properties = d
        return discovered_vuln_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
