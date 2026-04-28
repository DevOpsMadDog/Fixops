from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.generate_pr_request_finding import GeneratePRRequestFinding


T = TypeVar("T", bound="GeneratePRRequest")


@_attrs_define
class GeneratePRRequest:
    """Generate a PR from a single security finding.

    Attributes:
        finding (GeneratePRRequestFinding): Security finding dict (Snyk/Trivy/Grype/Dependabot shape)
        repo (str): Target repository name, e.g. 'Fixops'
        owner (str): GitHub owner or org, e.g. 'DevOpsMadDog'
        org_id (str | Unset): Tenant identifier Default: 'default'.
    """

    finding: GeneratePRRequestFinding
    repo: str
    owner: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        repo = self.repo

        owner = self.owner

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
                "repo": repo,
                "owner": owner,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.generate_pr_request_finding import GeneratePRRequestFinding

        d = dict(src_dict)
        finding = GeneratePRRequestFinding.from_dict(d.pop("finding"))

        repo = d.pop("repo")

        owner = d.pop("owner")

        org_id = d.pop("org_id", UNSET)

        generate_pr_request = cls(
            finding=finding,
            repo=repo,
            owner=owner,
            org_id=org_id,
        )

        generate_pr_request.additional_properties = d
        return generate_pr_request

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
