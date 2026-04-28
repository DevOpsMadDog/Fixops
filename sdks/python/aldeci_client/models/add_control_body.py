from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddControlBody")


@_attrs_define
class AddControlBody:
    """
    Attributes:
        control_name (str): Control name or identifier
        domain (str): Security domain (e.g. IAM, Network, Crypto)
        implementation_status (str | Unset): implemented | partial | not_implemented | compensating Default:
            'not_implemented'.
        effectiveness (float | Unset): Effectiveness score 0–100 Default: 0.0.
        gaps (str | Unset): Description of gaps Default: ''.
    """

    control_name: str
    domain: str
    implementation_status: str | Unset = "not_implemented"
    effectiveness: float | Unset = 0.0
    gaps: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_name = self.control_name

        domain = self.domain

        implementation_status = self.implementation_status

        effectiveness = self.effectiveness

        gaps = self.gaps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_name": control_name,
                "domain": domain,
            }
        )
        if implementation_status is not UNSET:
            field_dict["implementation_status"] = implementation_status
        if effectiveness is not UNSET:
            field_dict["effectiveness"] = effectiveness
        if gaps is not UNSET:
            field_dict["gaps"] = gaps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_name = d.pop("control_name")

        domain = d.pop("domain")

        implementation_status = d.pop("implementation_status", UNSET)

        effectiveness = d.pop("effectiveness", UNSET)

        gaps = d.pop("gaps", UNSET)

        add_control_body = cls(
            control_name=control_name,
            domain=domain,
            implementation_status=implementation_status,
            effectiveness=effectiveness,
            gaps=gaps,
        )

        add_control_body.additional_properties = d
        return add_control_body

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
