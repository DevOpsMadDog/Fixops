from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SLAResponse")


@_attrs_define
class SLAResponse:
    """
    Attributes:
        app_id (str):
        component (None | str):
        severity (str):
        sla_string (str):
        deadline_utc (str):
    """

    app_id: str
    component: None | str
    severity: str
    sla_string: str
    deadline_utc: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        component: None | str
        component = self.component

        severity = self.severity

        sla_string = self.sla_string

        deadline_utc = self.deadline_utc

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
                "component": component,
                "severity": severity,
                "sla_string": sla_string,
                "deadline_utc": deadline_utc,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_id = d.pop("app_id")

        def _parse_component(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        component = _parse_component(d.pop("component"))

        severity = d.pop("severity")

        sla_string = d.pop("sla_string")

        deadline_utc = d.pop("deadline_utc")

        sla_response = cls(
            app_id=app_id,
            component=component,
            severity=severity,
            sla_string=sla_string,
            deadline_utc=deadline_utc,
        )

        sla_response.additional_properties = d
        return sla_response

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
