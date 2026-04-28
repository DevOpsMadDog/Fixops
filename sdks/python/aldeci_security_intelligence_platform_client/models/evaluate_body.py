from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.evaluate_body_entities_item import EvaluateBodyEntitiesItem


T = TypeVar("T", bound="EvaluateBody")


@_attrs_define
class EvaluateBody:
    """Body for POST /evaluate.

    Optional list of entity attribute payloads to register first, then evaluate.
    Each entry needs ``entity_ref`` and ``attributes``.

        Attributes:
            entities (list[EvaluateBodyEntitiesItem] | Unset):
    """

    entities: list[EvaluateBodyEntitiesItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entities: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.entities, Unset):
            entities = []
            for entities_item_data in self.entities:
                entities_item = entities_item_data.to_dict()
                entities.append(entities_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if entities is not UNSET:
            field_dict["entities"] = entities

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_body_entities_item import EvaluateBodyEntitiesItem

        d = dict(src_dict)
        _entities = d.pop("entities", UNSET)
        entities: list[EvaluateBodyEntitiesItem] | Unset = UNSET
        if _entities is not UNSET:
            entities = []
            for entities_item_data in _entities:
                entities_item = EvaluateBodyEntitiesItem.from_dict(entities_item_data)

                entities.append(entities_item)

        evaluate_body = cls(
            entities=entities,
        )

        evaluate_body.additional_properties = d
        return evaluate_body

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
