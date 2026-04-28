from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterEmployeeRequest")


@_attrs_define
class RegisterEmployeeRequest:
    """
    Attributes:
        employee_id (str):
        name (str | Unset):  Default: ''.
        department (str | Unset):  Default: ''.
        role (str | Unset):  Default: ''.
        risk_level (str | Unset):  Default: 'standard'.
        last_training_at (None | str | Unset):
        phishing_click_rate (float | Unset):  Default: 0.0.
        training_completion_pct (float | Unset):  Default: 0.0.
    """

    employee_id: str
    name: str | Unset = ""
    department: str | Unset = ""
    role: str | Unset = ""
    risk_level: str | Unset = "standard"
    last_training_at: None | str | Unset = UNSET
    phishing_click_rate: float | Unset = 0.0
    training_completion_pct: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        employee_id = self.employee_id

        name = self.name

        department = self.department

        role = self.role

        risk_level = self.risk_level

        last_training_at: None | str | Unset
        if isinstance(self.last_training_at, Unset):
            last_training_at = UNSET
        else:
            last_training_at = self.last_training_at

        phishing_click_rate = self.phishing_click_rate

        training_completion_pct = self.training_completion_pct

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "employee_id": employee_id,
            }
        )
        if name is not UNSET:
            field_dict["name"] = name
        if department is not UNSET:
            field_dict["department"] = department
        if role is not UNSET:
            field_dict["role"] = role
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if last_training_at is not UNSET:
            field_dict["last_training_at"] = last_training_at
        if phishing_click_rate is not UNSET:
            field_dict["phishing_click_rate"] = phishing_click_rate
        if training_completion_pct is not UNSET:
            field_dict["training_completion_pct"] = training_completion_pct

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        employee_id = d.pop("employee_id")

        name = d.pop("name", UNSET)

        department = d.pop("department", UNSET)

        role = d.pop("role", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        def _parse_last_training_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_training_at = _parse_last_training_at(d.pop("last_training_at", UNSET))

        phishing_click_rate = d.pop("phishing_click_rate", UNSET)

        training_completion_pct = d.pop("training_completion_pct", UNSET)

        register_employee_request = cls(
            employee_id=employee_id,
            name=name,
            department=department,
            role=role,
            risk_level=risk_level,
            last_training_at=last_training_at,
            phishing_click_rate=phishing_click_rate,
            training_completion_pct=training_completion_pct,
        )

        register_employee_request.additional_properties = d
        return register_employee_request

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
