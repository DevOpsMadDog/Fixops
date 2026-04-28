from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MitigationCreate")


@_attrs_define
class MitigationCreate:
    """
    Attributes:
        mitigation_name (str):
        mitigation_type (str | Unset):  Default: 'technical'.
        effectiveness (float | Unset):  Default: 0.5.
        cost_estimate (float | Unset):  Default: 0.0.
    """

    mitigation_name: str
    mitigation_type: str | Unset = "technical"
    effectiveness: float | Unset = 0.5
    cost_estimate: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mitigation_name = self.mitigation_name

        mitigation_type = self.mitigation_type

        effectiveness = self.effectiveness

        cost_estimate = self.cost_estimate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "mitigation_name": mitigation_name,
            }
        )
        if mitigation_type is not UNSET:
            field_dict["mitigation_type"] = mitigation_type
        if effectiveness is not UNSET:
            field_dict["effectiveness"] = effectiveness
        if cost_estimate is not UNSET:
            field_dict["cost_estimate"] = cost_estimate

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        mitigation_name = d.pop("mitigation_name")

        mitigation_type = d.pop("mitigation_type", UNSET)

        effectiveness = d.pop("effectiveness", UNSET)

        cost_estimate = d.pop("cost_estimate", UNSET)

        mitigation_create = cls(
            mitigation_name=mitigation_name,
            mitigation_type=mitigation_type,
            effectiveness=effectiveness,
            cost_estimate=cost_estimate,
        )

        mitigation_create.additional_properties = d
        return mitigation_create

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
