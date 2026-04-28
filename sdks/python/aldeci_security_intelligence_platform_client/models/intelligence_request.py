from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IntelligenceRequest")


@_attrs_define
class IntelligenceRequest:
    """
    Attributes:
        org_id (str):
        target (str):
        cve_ids (list[str]):
        include_osint (bool | Unset):  Default: True.
    """

    org_id: str
    target: str
    cve_ids: list[str]
    include_osint: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        target = self.target

        cve_ids = self.cve_ids

        include_osint = self.include_osint

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "target": target,
                "cve_ids": cve_ids,
            }
        )
        if include_osint is not UNSET:
            field_dict["include_osint"] = include_osint

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        target = d.pop("target")

        cve_ids = cast(list[str], d.pop("cve_ids"))

        include_osint = d.pop("include_osint", UNSET)

        intelligence_request = cls(
            org_id=org_id,
            target=target,
            cve_ids=cve_ids,
            include_osint=include_osint,
        )

        intelligence_request.additional_properties = d
        return intelligence_request

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
