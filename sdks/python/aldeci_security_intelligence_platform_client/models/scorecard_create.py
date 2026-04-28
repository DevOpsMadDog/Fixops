from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dimension_input import DimensionInput


T = TypeVar("T", bound="ScorecardCreate")


@_attrs_define
class ScorecardCreate:
    """
    Attributes:
        entity_id (str):
        entity_type (str | Unset): team|asset|project|vendor|service Default: 'team'.
        entity_name (str | Unset):  Default: ''.
        period_label (str | Unset): e.g. '2026-Q1' Default: ''.
        dimensions (list[DimensionInput] | Unset):
    """

    entity_id: str
    entity_type: str | Unset = "team"
    entity_name: str | Unset = ""
    period_label: str | Unset = ""
    dimensions: list[DimensionInput] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        entity_type = self.entity_type

        entity_name = self.entity_name

        period_label = self.period_label

        dimensions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.dimensions, Unset):
            dimensions = []
            for dimensions_item_data in self.dimensions:
                dimensions_item = dimensions_item_data.to_dict()
                dimensions.append(dimensions_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
            }
        )
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if entity_name is not UNSET:
            field_dict["entity_name"] = entity_name
        if period_label is not UNSET:
            field_dict["period_label"] = period_label
        if dimensions is not UNSET:
            field_dict["dimensions"] = dimensions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dimension_input import DimensionInput

        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        entity_type = d.pop("entity_type", UNSET)

        entity_name = d.pop("entity_name", UNSET)

        period_label = d.pop("period_label", UNSET)

        _dimensions = d.pop("dimensions", UNSET)
        dimensions: list[DimensionInput] | Unset = UNSET
        if _dimensions is not UNSET:
            dimensions = []
            for dimensions_item_data in _dimensions:
                dimensions_item = DimensionInput.from_dict(dimensions_item_data)

                dimensions.append(dimensions_item)

        scorecard_create = cls(
            entity_id=entity_id,
            entity_type=entity_type,
            entity_name=entity_name,
            period_label=period_label,
            dimensions=dimensions,
        )

        scorecard_create.additional_properties = d
        return scorecard_create

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
