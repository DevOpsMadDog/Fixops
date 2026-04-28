from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RiskIn")


@_attrs_define
class RiskIn:
    """
    Attributes:
        supplier_id (str | Unset):  Default: ''.
        risk_type (str | Unset):  Default: 'single_source'.
        severity (str | Unset):  Default: 'medium'.
        description (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'open'.
    """

    supplier_id: str | Unset = ""
    risk_type: str | Unset = "single_source"
    severity: str | Unset = "medium"
    description: str | Unset = ""
    status: str | Unset = "open"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        supplier_id = self.supplier_id

        risk_type = self.risk_type

        severity = self.severity

        description = self.description

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if supplier_id is not UNSET:
            field_dict["supplier_id"] = supplier_id
        if risk_type is not UNSET:
            field_dict["risk_type"] = risk_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        supplier_id = d.pop("supplier_id", UNSET)

        risk_type = d.pop("risk_type", UNSET)

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        status = d.pop("status", UNSET)

        risk_in = cls(
            supplier_id=supplier_id,
            risk_type=risk_type,
            severity=severity,
            description=description,
            status=status,
        )

        risk_in.additional_properties = d
        return risk_in

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
