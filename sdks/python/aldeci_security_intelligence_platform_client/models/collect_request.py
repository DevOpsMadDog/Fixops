from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CollectRequest")


@_attrs_define
class CollectRequest:
    """
    Attributes:
        org_id (str):
        control_id (str):
        framework (str | Unset):  Default: 'SOC2'.
    """

    org_id: str
    control_id: str
    framework: str | Unset = "SOC2"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        control_id = self.control_id

        framework = self.framework

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "control_id": control_id,
            }
        )
        if framework is not UNSET:
            field_dict["framework"] = framework

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        control_id = d.pop("control_id")

        framework = d.pop("framework", UNSET)

        collect_request = cls(
            org_id=org_id,
            control_id=control_id,
            framework=framework,
        )

        collect_request.additional_properties = d
        return collect_request

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
