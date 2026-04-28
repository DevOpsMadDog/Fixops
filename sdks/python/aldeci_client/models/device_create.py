from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeviceCreate")


@_attrs_define
class DeviceCreate:
    """
    Attributes:
        device_name (str | Unset):  Default: ''.
        device_type (str | Unset):  Default: 'embedded'.
        manufacturer (str | Unset):  Default: ''.
        model (str | Unset):  Default: ''.
        firmware_version (str | Unset):  Default: ''.
        last_scanned (None | str | Unset):
        risk_score (float | Unset):  Default: 50.0.
        risk_level (str | Unset):  Default: 'medium'.
        status (str | Unset):  Default: 'active'.
    """

    device_name: str | Unset = ""
    device_type: str | Unset = "embedded"
    manufacturer: str | Unset = ""
    model: str | Unset = ""
    firmware_version: str | Unset = ""
    last_scanned: None | str | Unset = UNSET
    risk_score: float | Unset = 50.0
    risk_level: str | Unset = "medium"
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        device_name = self.device_name

        device_type = self.device_type

        manufacturer = self.manufacturer

        model = self.model

        firmware_version = self.firmware_version

        last_scanned: None | str | Unset
        if isinstance(self.last_scanned, Unset):
            last_scanned = UNSET
        else:
            last_scanned = self.last_scanned

        risk_score = self.risk_score

        risk_level = self.risk_level

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if device_name is not UNSET:
            field_dict["device_name"] = device_name
        if device_type is not UNSET:
            field_dict["device_type"] = device_type
        if manufacturer is not UNSET:
            field_dict["manufacturer"] = manufacturer
        if model is not UNSET:
            field_dict["model"] = model
        if firmware_version is not UNSET:
            field_dict["firmware_version"] = firmware_version
        if last_scanned is not UNSET:
            field_dict["last_scanned"] = last_scanned
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        device_name = d.pop("device_name", UNSET)

        device_type = d.pop("device_type", UNSET)

        manufacturer = d.pop("manufacturer", UNSET)

        model = d.pop("model", UNSET)

        firmware_version = d.pop("firmware_version", UNSET)

        def _parse_last_scanned(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_scanned = _parse_last_scanned(d.pop("last_scanned", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        status = d.pop("status", UNSET)

        device_create = cls(
            device_name=device_name,
            device_type=device_type,
            manufacturer=manufacturer,
            model=model,
            firmware_version=firmware_version,
            last_scanned=last_scanned,
            risk_score=risk_score,
            risk_level=risk_level,
            status=status,
        )

        device_create.additional_properties = d
        return device_create

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
