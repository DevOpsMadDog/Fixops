from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateKRIRequest")


@_attrs_define
class CreateKRIRequest:
    """
    Attributes:
        risk_id (str): ID of the associated risk
        name (str): KRI name
        warning_threshold (float): Warning level threshold
        breach_threshold (float): Breach level threshold
        description (str | Unset):  Default: ''.
        unit (str | Unset): Measurement unit, e.g. 'count', '%' Default: ''.
        current_value (float | Unset): Current measured value Default: 0.0.
        direction (str | Unset): higher_is_worse | lower_is_worse Default: 'higher_is_worse'.
        org_id (str | Unset):  Default: 'default'.
    """

    risk_id: str
    name: str
    warning_threshold: float
    breach_threshold: float
    description: str | Unset = ""
    unit: str | Unset = ""
    current_value: float | Unset = 0.0
    direction: str | Unset = "higher_is_worse"
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        risk_id = self.risk_id

        name = self.name

        warning_threshold = self.warning_threshold

        breach_threshold = self.breach_threshold

        description = self.description

        unit = self.unit

        current_value = self.current_value

        direction = self.direction

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "risk_id": risk_id,
                "name": name,
                "warning_threshold": warning_threshold,
                "breach_threshold": breach_threshold,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if unit is not UNSET:
            field_dict["unit"] = unit
        if current_value is not UNSET:
            field_dict["current_value"] = current_value
        if direction is not UNSET:
            field_dict["direction"] = direction
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        risk_id = d.pop("risk_id")

        name = d.pop("name")

        warning_threshold = d.pop("warning_threshold")

        breach_threshold = d.pop("breach_threshold")

        description = d.pop("description", UNSET)

        unit = d.pop("unit", UNSET)

        current_value = d.pop("current_value", UNSET)

        direction = d.pop("direction", UNSET)

        org_id = d.pop("org_id", UNSET)

        create_kri_request = cls(
            risk_id=risk_id,
            name=name,
            warning_threshold=warning_threshold,
            breach_threshold=breach_threshold,
            description=description,
            unit=unit,
            current_value=current_value,
            direction=direction,
            org_id=org_id,
        )

        create_kri_request.additional_properties = d
        return create_kri_request

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
