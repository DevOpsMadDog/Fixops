from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DarkWebMonitorRequest")


@_attrs_define
class DarkWebMonitorRequest:
    """
    Attributes:
        subsidiary_name (str): Subsidiary to monitor on dark-web sources
        org_id (str | Unset): Organisation ID Default: 'default'.
        keywords (list[str] | Unset): Keywords (brands, email domains, product names) to watch for
    """

    subsidiary_name: str
    org_id: str | Unset = "default"
    keywords: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subsidiary_name = self.subsidiary_name

        org_id = self.org_id

        keywords: list[str] | Unset = UNSET
        if not isinstance(self.keywords, Unset):
            keywords = self.keywords

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subsidiary_name": subsidiary_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if keywords is not UNSET:
            field_dict["keywords"] = keywords

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subsidiary_name = d.pop("subsidiary_name")

        org_id = d.pop("org_id", UNSET)

        keywords = cast(list[str], d.pop("keywords", UNSET))

        dark_web_monitor_request = cls(
            subsidiary_name=subsidiary_name,
            org_id=org_id,
            keywords=keywords,
        )

        dark_web_monitor_request.additional_properties = d
        return dark_web_monitor_request

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
