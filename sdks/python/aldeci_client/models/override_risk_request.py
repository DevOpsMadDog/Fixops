from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.change_risk_level import ChangeRiskLevel

T = TypeVar("T", bound="OverrideRiskRequest")


@_attrs_define
class OverrideRiskRequest:
    """
    Attributes:
        actor_id (str):
        actor_name (str):
        new_risk (ChangeRiskLevel): ITIL risk classification.
        justification (str):
    """

    actor_id: str
    actor_name: str
    new_risk: ChangeRiskLevel
    justification: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actor_id = self.actor_id

        actor_name = self.actor_name

        new_risk = self.new_risk.value

        justification = self.justification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "actor_id": actor_id,
                "actor_name": actor_name,
                "new_risk": new_risk,
                "justification": justification,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actor_id = d.pop("actor_id")

        actor_name = d.pop("actor_name")

        new_risk = ChangeRiskLevel(d.pop("new_risk"))

        justification = d.pop("justification")

        override_risk_request = cls(
            actor_id=actor_id,
            actor_name=actor_name,
            new_risk=new_risk,
            justification=justification,
        )

        override_risk_request.additional_properties = d
        return override_risk_request

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
