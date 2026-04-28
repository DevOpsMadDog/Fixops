from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReleaseReq")


@_attrs_define
class ReleaseReq:
    """
    Attributes:
        package_purl (str):
        released_by (str):
        reason (str):
        org_id (str | Unset):  Default: 'default'.
    """

    package_purl: str
    released_by: str
    reason: str
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_purl = self.package_purl

        released_by = self.released_by

        reason = self.reason

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_purl": package_purl,
                "released_by": released_by,
                "reason": reason,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_purl = d.pop("package_purl")

        released_by = d.pop("released_by")

        reason = d.pop("reason")

        org_id = d.pop("org_id", UNSET)

        release_req = cls(
            package_purl=package_purl,
            released_by=released_by,
            reason=reason,
            org_id=org_id,
        )

        release_req.additional_properties = d
        return release_req

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
