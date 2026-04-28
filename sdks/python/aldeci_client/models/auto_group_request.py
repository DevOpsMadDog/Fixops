from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AutoGroupRequest")


@_attrs_define
class AutoGroupRequest:
    """
    Attributes:
        org_id (str):
        window_seconds (int | Unset):  Default: 300.
        ingest_into_correlation (bool | Unset):  Default: True.
    """

    org_id: str
    window_seconds: int | Unset = 300
    ingest_into_correlation: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        window_seconds = self.window_seconds

        ingest_into_correlation = self.ingest_into_correlation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
            }
        )
        if window_seconds is not UNSET:
            field_dict["window_seconds"] = window_seconds
        if ingest_into_correlation is not UNSET:
            field_dict["ingest_into_correlation"] = ingest_into_correlation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        window_seconds = d.pop("window_seconds", UNSET)

        ingest_into_correlation = d.pop("ingest_into_correlation", UNSET)

        auto_group_request = cls(
            org_id=org_id,
            window_seconds=window_seconds,
            ingest_into_correlation=ingest_into_correlation,
        )

        auto_group_request.additional_properties = d
        return auto_group_request

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
