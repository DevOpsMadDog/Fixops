from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.gap_input import GapInput


T = TypeVar("T", bound="GeneratePlanRequest")


@_attrs_define
class GeneratePlanRequest:
    """
    Attributes:
        gaps (list[GapInput]):
    """

    gaps: list[GapInput]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        gaps = []
        for gaps_item_data in self.gaps:
            gaps_item = gaps_item_data.to_dict()
            gaps.append(gaps_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "gaps": gaps,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gap_input import GapInput

        d = dict(src_dict)
        gaps = []
        _gaps = d.pop("gaps")
        for gaps_item_data in _gaps:
            gaps_item = GapInput.from_dict(gaps_item_data)

            gaps.append(gaps_item)

        generate_plan_request = cls(
            gaps=gaps,
        )

        generate_plan_request.additional_properties = d
        return generate_plan_request

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
