from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.scan_submit_request_findings_item import ScanSubmitRequestFindingsItem


T = TypeVar("T", bound="ScanSubmitRequest")


@_attrs_define
class ScanSubmitRequest:
    """Payload sent by a CI job to trigger a scan evaluation.

    Attributes:
        repo (str): Repository slug (owner/name or group/project)
        branch (str | Unset): Branch or ref name Default: 'main'.
        commit_sha (str | Unset): Full commit SHA Default: ''.
        policy_id (str | Unset): Policy UUID to evaluate against Default: ''.
        findings (list[ScanSubmitRequestFindingsItem] | Unset): List of finding dicts (severity, category, title, …)
        duration_ms (int | Unset): Scan duration in milliseconds Default: 0.
    """

    repo: str
    branch: str | Unset = "main"
    commit_sha: str | Unset = ""
    policy_id: str | Unset = ""
    findings: list[ScanSubmitRequestFindingsItem] | Unset = UNSET
    duration_ms: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo = self.repo

        branch = self.branch

        commit_sha = self.commit_sha

        policy_id = self.policy_id

        findings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = []
            for findings_item_data in self.findings:
                findings_item = findings_item_data.to_dict()
                findings.append(findings_item)

        duration_ms = self.duration_ms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo": repo,
            }
        )
        if branch is not UNSET:
            field_dict["branch"] = branch
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if findings is not UNSET:
            field_dict["findings"] = findings
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.scan_submit_request_findings_item import ScanSubmitRequestFindingsItem

        d = dict(src_dict)
        repo = d.pop("repo")

        branch = d.pop("branch", UNSET)

        commit_sha = d.pop("commit_sha", UNSET)

        policy_id = d.pop("policy_id", UNSET)

        _findings = d.pop("findings", UNSET)
        findings: list[ScanSubmitRequestFindingsItem] | Unset = UNSET
        if _findings is not UNSET:
            findings = []
            for findings_item_data in _findings:
                findings_item = ScanSubmitRequestFindingsItem.from_dict(findings_item_data)

                findings.append(findings_item)

        duration_ms = d.pop("duration_ms", UNSET)

        scan_submit_request = cls(
            repo=repo,
            branch=branch,
            commit_sha=commit_sha,
            policy_id=policy_id,
            findings=findings,
            duration_ms=duration_ms,
        )

        scan_submit_request.additional_properties = d
        return scan_submit_request

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
