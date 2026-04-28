from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_verify_request_finding import FindingVerifyRequestFinding


T = TypeVar("T", bound="FindingVerifyRequest")


@_attrs_define
class FindingVerifyRequest:
    """Request model for finding verification.

    Attributes:
        finding (FindingVerifyRequestFinding): Finding object to verify
        target_url (str | Unset): Target URL Default: ''.
    """

    finding: FindingVerifyRequestFinding
    target_url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        target_url = self.target_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
            }
        )
        if target_url is not UNSET:
            field_dict["target_url"] = target_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_verify_request_finding import FindingVerifyRequestFinding

        d = dict(src_dict)
        finding = FindingVerifyRequestFinding.from_dict(d.pop("finding"))

        target_url = d.pop("target_url", UNSET)

        finding_verify_request = cls(
            finding=finding,
            target_url=target_url,
        )

        finding_verify_request.additional_properties = d
        return finding_verify_request

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
