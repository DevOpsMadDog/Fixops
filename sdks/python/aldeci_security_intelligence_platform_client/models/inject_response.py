from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="InjectResponse")


@_attrs_define
class InjectResponse:
    """Response after injecting a synthetic vulnerability.

    Attributes:
        drill_id (str):
        scenario_id (str):
        scenario_name (str):
        target_component (str):
        org_id (str):
        status (str):
        severity (str):
        synthetic_finding_id (str):
        expires_at (str):
        message (str):
        injected_at (None | str | Unset):
    """

    drill_id: str
    scenario_id: str
    scenario_name: str
    target_component: str
    org_id: str
    status: str
    severity: str
    synthetic_finding_id: str
    expires_at: str
    message: str
    injected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        drill_id = self.drill_id

        scenario_id = self.scenario_id

        scenario_name = self.scenario_name

        target_component = self.target_component

        org_id = self.org_id

        status = self.status

        severity = self.severity

        synthetic_finding_id = self.synthetic_finding_id

        expires_at = self.expires_at

        message = self.message

        injected_at: None | str | Unset
        if isinstance(self.injected_at, Unset):
            injected_at = UNSET
        else:
            injected_at = self.injected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "drill_id": drill_id,
                "scenario_id": scenario_id,
                "scenario_name": scenario_name,
                "target_component": target_component,
                "org_id": org_id,
                "status": status,
                "severity": severity,
                "synthetic_finding_id": synthetic_finding_id,
                "expires_at": expires_at,
                "message": message,
            }
        )
        if injected_at is not UNSET:
            field_dict["injected_at"] = injected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        drill_id = d.pop("drill_id")

        scenario_id = d.pop("scenario_id")

        scenario_name = d.pop("scenario_name")

        target_component = d.pop("target_component")

        org_id = d.pop("org_id")

        status = d.pop("status")

        severity = d.pop("severity")

        synthetic_finding_id = d.pop("synthetic_finding_id")

        expires_at = d.pop("expires_at")

        message = d.pop("message")

        def _parse_injected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        injected_at = _parse_injected_at(d.pop("injected_at", UNSET))

        inject_response = cls(
            drill_id=drill_id,
            scenario_id=scenario_id,
            scenario_name=scenario_name,
            target_component=target_component,
            org_id=org_id,
            status=status,
            severity=severity,
            synthetic_finding_id=synthetic_finding_id,
            expires_at=expires_at,
            message=message,
            injected_at=injected_at,
        )

        inject_response.additional_properties = d
        return inject_response

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
