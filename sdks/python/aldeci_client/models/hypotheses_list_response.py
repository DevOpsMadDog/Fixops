from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.hunt_hypothesis import HuntHypothesis


T = TypeVar("T", bound="HypothesesListResponse")


@_attrs_define
class HypothesesListResponse:
    """
    Attributes:
        hypotheses (list[HuntHypothesis]):
        total (int):
    """

    hypotheses: list[HuntHypothesis]
    total: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hypotheses = []
        for hypotheses_item_data in self.hypotheses:
            hypotheses_item = hypotheses_item_data.to_dict()
            hypotheses.append(hypotheses_item)

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hypotheses": hypotheses,
                "total": total,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.hunt_hypothesis import HuntHypothesis

        d = dict(src_dict)
        hypotheses = []
        _hypotheses = d.pop("hypotheses")
        for hypotheses_item_data in _hypotheses:
            hypotheses_item = HuntHypothesis.from_dict(hypotheses_item_data)

            hypotheses.append(hypotheses_item)

        total = d.pop("total")

        hypotheses_list_response = cls(
            hypotheses=hypotheses,
            total=total,
        )

        hypotheses_list_response.additional_properties = d
        return hypotheses_list_response

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
