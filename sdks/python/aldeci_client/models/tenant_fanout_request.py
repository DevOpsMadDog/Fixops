from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TenantFanoutRequest")


@_attrs_define
class TenantFanoutRequest:
    """
    Attributes:
        org_ids (list[str]):
        events_per_org (int | Unset):  Default: 4.
        force_fallback (bool | Unset):  Default: True.
    """

    org_ids: list[str]
    events_per_org: int | Unset = 4
    force_fallback: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_ids = self.org_ids

        events_per_org = self.events_per_org

        force_fallback = self.force_fallback

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_ids": org_ids,
            }
        )
        if events_per_org is not UNSET:
            field_dict["events_per_org"] = events_per_org
        if force_fallback is not UNSET:
            field_dict["force_fallback"] = force_fallback

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_ids = cast(list[str], d.pop("org_ids"))

        events_per_org = d.pop("events_per_org", UNSET)

        force_fallback = d.pop("force_fallback", UNSET)

        tenant_fanout_request = cls(
            org_ids=org_ids,
            events_per_org=events_per_org,
            force_fallback=force_fallback,
        )

        tenant_fanout_request.additional_properties = d
        return tenant_fanout_request

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
