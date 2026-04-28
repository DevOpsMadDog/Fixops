from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.gate_check_request_findings_type_0_item import GateCheckRequestFindingsType0Item
    from ..models.gate_check_request_sarif_type_0 import GateCheckRequestSarifType0
    from ..models.gate_check_request_sbom_type_0 import GateCheckRequestSbomType0
    from ..models.policy_thresholds import PolicyThresholds


T = TypeVar("T", bound="GateCheckRequest")


@_attrs_define
class GateCheckRequest:
    """Primary gate check request — accepts multiple input formats.

    Attributes:
        repository (str): Repository identifier (owner/repo)
        commit_sha (str | Unset): Commit SHA being evaluated Default: ''.
        branch (str | Unset): Branch name Default: 'main'.
        pull_request (int | None | Unset): PR number (if applicable)
        sarif (GateCheckRequestSarifType0 | None | Unset): SARIF v2.1.0 scan results
        findings (list[GateCheckRequestFindingsType0Item] | None | Unset): Pre-parsed findings list
        sbom (GateCheckRequestSbomType0 | None | Unset): CycloneDX or SPDX SBOM
        diff (None | str | Unset): Unified diff content for material change analysis
        policy_id (None | str | Unset): Named policy ID to evaluate against
        thresholds (None | PolicyThresholds | Unset): Inline threshold overrides
    """

    repository: str
    commit_sha: str | Unset = ""
    branch: str | Unset = "main"
    pull_request: int | None | Unset = UNSET
    sarif: GateCheckRequestSarifType0 | None | Unset = UNSET
    findings: list[GateCheckRequestFindingsType0Item] | None | Unset = UNSET
    sbom: GateCheckRequestSbomType0 | None | Unset = UNSET
    diff: None | str | Unset = UNSET
    policy_id: None | str | Unset = UNSET
    thresholds: None | PolicyThresholds | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.gate_check_request_sarif_type_0 import GateCheckRequestSarifType0
        from ..models.gate_check_request_sbom_type_0 import GateCheckRequestSbomType0
        from ..models.policy_thresholds import PolicyThresholds

        repository = self.repository

        commit_sha = self.commit_sha

        branch = self.branch

        pull_request: int | None | Unset
        if isinstance(self.pull_request, Unset):
            pull_request = UNSET
        else:
            pull_request = self.pull_request

        sarif: dict[str, Any] | None | Unset
        if isinstance(self.sarif, Unset):
            sarif = UNSET
        elif isinstance(self.sarif, GateCheckRequestSarifType0):
            sarif = self.sarif.to_dict()
        else:
            sarif = self.sarif

        findings: list[dict[str, Any]] | None | Unset
        if isinstance(self.findings, Unset):
            findings = UNSET
        elif isinstance(self.findings, list):
            findings = []
            for findings_type_0_item_data in self.findings:
                findings_type_0_item = findings_type_0_item_data.to_dict()
                findings.append(findings_type_0_item)

        else:
            findings = self.findings

        sbom: dict[str, Any] | None | Unset
        if isinstance(self.sbom, Unset):
            sbom = UNSET
        elif isinstance(self.sbom, GateCheckRequestSbomType0):
            sbom = self.sbom.to_dict()
        else:
            sbom = self.sbom

        diff: None | str | Unset
        if isinstance(self.diff, Unset):
            diff = UNSET
        else:
            diff = self.diff

        policy_id: None | str | Unset
        if isinstance(self.policy_id, Unset):
            policy_id = UNSET
        else:
            policy_id = self.policy_id

        thresholds: dict[str, Any] | None | Unset
        if isinstance(self.thresholds, Unset):
            thresholds = UNSET
        elif isinstance(self.thresholds, PolicyThresholds):
            thresholds = self.thresholds.to_dict()
        else:
            thresholds = self.thresholds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repository": repository,
            }
        )
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if branch is not UNSET:
            field_dict["branch"] = branch
        if pull_request is not UNSET:
            field_dict["pull_request"] = pull_request
        if sarif is not UNSET:
            field_dict["sarif"] = sarif
        if findings is not UNSET:
            field_dict["findings"] = findings
        if sbom is not UNSET:
            field_dict["sbom"] = sbom
        if diff is not UNSET:
            field_dict["diff"] = diff
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if thresholds is not UNSET:
            field_dict["thresholds"] = thresholds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gate_check_request_findings_type_0_item import GateCheckRequestFindingsType0Item
        from ..models.gate_check_request_sarif_type_0 import GateCheckRequestSarifType0
        from ..models.gate_check_request_sbom_type_0 import GateCheckRequestSbomType0
        from ..models.policy_thresholds import PolicyThresholds

        d = dict(src_dict)
        repository = d.pop("repository")

        commit_sha = d.pop("commit_sha", UNSET)

        branch = d.pop("branch", UNSET)

        def _parse_pull_request(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        pull_request = _parse_pull_request(d.pop("pull_request", UNSET))

        def _parse_sarif(data: object) -> GateCheckRequestSarifType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sarif_type_0 = GateCheckRequestSarifType0.from_dict(data)

                return sarif_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GateCheckRequestSarifType0 | None | Unset, data)

        sarif = _parse_sarif(d.pop("sarif", UNSET))

        def _parse_findings(data: object) -> list[GateCheckRequestFindingsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                findings_type_0 = []
                _findings_type_0 = data
                for findings_type_0_item_data in _findings_type_0:
                    findings_type_0_item = GateCheckRequestFindingsType0Item.from_dict(findings_type_0_item_data)

                    findings_type_0.append(findings_type_0_item)

                return findings_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[GateCheckRequestFindingsType0Item] | None | Unset, data)

        findings = _parse_findings(d.pop("findings", UNSET))

        def _parse_sbom(data: object) -> GateCheckRequestSbomType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sbom_type_0 = GateCheckRequestSbomType0.from_dict(data)

                return sbom_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GateCheckRequestSbomType0 | None | Unset, data)

        sbom = _parse_sbom(d.pop("sbom", UNSET))

        def _parse_diff(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        diff = _parse_diff(d.pop("diff", UNSET))

        def _parse_policy_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_id = _parse_policy_id(d.pop("policy_id", UNSET))

        def _parse_thresholds(data: object) -> None | PolicyThresholds | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                thresholds_type_0 = PolicyThresholds.from_dict(data)

                return thresholds_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyThresholds | Unset, data)

        thresholds = _parse_thresholds(d.pop("thresholds", UNSET))

        gate_check_request = cls(
            repository=repository,
            commit_sha=commit_sha,
            branch=branch,
            pull_request=pull_request,
            sarif=sarif,
            findings=findings,
            sbom=sbom,
            diff=diff,
            policy_id=policy_id,
            thresholds=thresholds,
        )

        gate_check_request.additional_properties = d
        return gate_check_request

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
