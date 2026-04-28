from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CloseEventRequest")


@_attrs_define
class CloseEventRequest:
    """
    Attributes:
        verdict (str): true_positive/false_positive/benign
        org_id (str | Unset):  Default: 'default'.
        resolution (str | Unset): Resolution description Default: ''.
    """

    verdict: str
    org_id: str | Unset = "default"
    resolution: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        verdict = self.verdict

        org_id = self.org_id

        resolution = self.resolution

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "verdict": verdict,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if resolution is not UNSET:
            field_dict["resolution"] = resolution

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        verdict = d.pop("verdict")

        org_id = d.pop("org_id", UNSET)

        resolution = d.pop("resolution", UNSET)

        close_event_request = cls(
            verdict=verdict,
            org_id=org_id,
            resolution=resolution,
        )

        close_event_request.additional_properties = d
        return close_event_request

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
