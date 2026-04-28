from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.batch_generate_pr_request_findings_item import BatchGeneratePRRequestFindingsItem


T = TypeVar("T", bound="BatchGeneratePRRequest")


@_attrs_define
class BatchGeneratePRRequest:
    """Batch-generate PRs from multiple security findings.

    Attributes:
        findings (list[BatchGeneratePRRequestFindingsItem]): List of security findings
        repo (str):
        owner (str):
        org_id (str | Unset):  Default: 'default'.
    """

    findings: list[BatchGeneratePRRequestFindingsItem]
    repo: str
    owner: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        repo = self.repo

        owner = self.owner

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
                "repo": repo,
                "owner": owner,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_generate_pr_request_findings_item import BatchGeneratePRRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = BatchGeneratePRRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        repo = d.pop("repo")

        owner = d.pop("owner")

        org_id = d.pop("org_id", UNSET)

        batch_generate_pr_request = cls(
            findings=findings,
            repo=repo,
            owner=owner,
            org_id=org_id,
        )

        batch_generate_pr_request.additional_properties = d
        return batch_generate_pr_request

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
