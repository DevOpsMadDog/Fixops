from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CaptureCreate")


@_attrs_define
class CaptureCreate:
    """
    Attributes:
        interface (str):
        filter_bpf (str | Unset):  Default: ''.
        duration_sec (int | Unset):  Default: 60.
    """

    interface: str
    filter_bpf: str | Unset = ""
    duration_sec: int | Unset = 60
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        interface = self.interface

        filter_bpf = self.filter_bpf

        duration_sec = self.duration_sec

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "interface": interface,
            }
        )
        if filter_bpf is not UNSET:
            field_dict["filter_bpf"] = filter_bpf
        if duration_sec is not UNSET:
            field_dict["duration_sec"] = duration_sec

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        interface = d.pop("interface")

        filter_bpf = d.pop("filter_bpf", UNSET)

        duration_sec = d.pop("duration_sec", UNSET)

        capture_create = cls(
            interface=interface,
            filter_bpf=filter_bpf,
            duration_sec=duration_sec,
        )

        capture_create.additional_properties = d
        return capture_create

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
