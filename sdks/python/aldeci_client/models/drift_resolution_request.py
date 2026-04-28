from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DriftResolutionRequest")


@_attrs_define
class DriftResolutionRequest:
    """
    Attributes:
        resolution (str):
        apply_fixops_status (bool | None | Unset):  Default: False.
        apply_external_status (bool | None | Unset):  Default: False.
    """

    resolution: str
    apply_fixops_status: bool | None | Unset = False
    apply_external_status: bool | None | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resolution = self.resolution

        apply_fixops_status: bool | None | Unset
        if isinstance(self.apply_fixops_status, Unset):
            apply_fixops_status = UNSET
        else:
            apply_fixops_status = self.apply_fixops_status

        apply_external_status: bool | None | Unset
        if isinstance(self.apply_external_status, Unset):
            apply_external_status = UNSET
        else:
            apply_external_status = self.apply_external_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resolution": resolution,
            }
        )
        if apply_fixops_status is not UNSET:
            field_dict["apply_fixops_status"] = apply_fixops_status
        if apply_external_status is not UNSET:
            field_dict["apply_external_status"] = apply_external_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        resolution = d.pop("resolution")

        def _parse_apply_fixops_status(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        apply_fixops_status = _parse_apply_fixops_status(d.pop("apply_fixops_status", UNSET))

        def _parse_apply_external_status(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        apply_external_status = _parse_apply_external_status(d.pop("apply_external_status", UNSET))

        drift_resolution_request = cls(
            resolution=resolution,
            apply_fixops_status=apply_fixops_status,
            apply_external_status=apply_external_status,
        )

        drift_resolution_request.additional_properties = d
        return drift_resolution_request

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
