from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.impact_analysis import ImpactAnalysis


T = TypeVar("T", bound="ImpactAssessRequest")


@_attrs_define
class ImpactAssessRequest:
    """
    Attributes:
        actor_id (str):
        actor_name (str):
        impact (ImpactAnalysis): Impact analysis for a change.
    """

    actor_id: str
    actor_name: str
    impact: ImpactAnalysis
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actor_id = self.actor_id

        actor_name = self.actor_name

        impact = self.impact.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "actor_id": actor_id,
                "actor_name": actor_name,
                "impact": impact,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.impact_analysis import ImpactAnalysis

        d = dict(src_dict)
        actor_id = d.pop("actor_id")

        actor_name = d.pop("actor_name")

        impact = ImpactAnalysis.from_dict(d.pop("impact"))

        impact_assess_request = cls(
            actor_id=actor_id,
            actor_name=actor_name,
            impact=impact,
        )

        impact_assess_request.additional_properties = d
        return impact_assess_request

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
