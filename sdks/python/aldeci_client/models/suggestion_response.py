from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.suggestion_response_action_type_0 import SuggestionResponseActionType0


T = TypeVar("T", bound="SuggestionResponse")


@_attrs_define
class SuggestionResponse:
    """AI-generated suggestion.

    Attributes:
        id (str):
        type_ (str):
        title (str):
        description (str):
        confidence (float):
        action (None | SuggestionResponseActionType0 | Unset):
    """

    id: str
    type_: str
    title: str
    description: str
    confidence: float
    action: None | SuggestionResponseActionType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.suggestion_response_action_type_0 import SuggestionResponseActionType0

        id = self.id

        type_ = self.type_

        title = self.title

        description = self.description

        confidence = self.confidence

        action: dict[str, Any] | None | Unset
        if isinstance(self.action, Unset):
            action = UNSET
        elif isinstance(self.action, SuggestionResponseActionType0):
            action = self.action.to_dict()
        else:
            action = self.action

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "type": type_,
                "title": title,
                "description": description,
                "confidence": confidence,
            }
        )
        if action is not UNSET:
            field_dict["action"] = action

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.suggestion_response_action_type_0 import SuggestionResponseActionType0

        d = dict(src_dict)
        id = d.pop("id")

        type_ = d.pop("type")

        title = d.pop("title")

        description = d.pop("description")

        confidence = d.pop("confidence")

        def _parse_action(data: object) -> None | SuggestionResponseActionType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                action_type_0 = SuggestionResponseActionType0.from_dict(data)

                return action_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SuggestionResponseActionType0 | Unset, data)

        action = _parse_action(d.pop("action", UNSET))

        suggestion_response = cls(
            id=id,
            type_=type_,
            title=title,
            description=description,
            confidence=confidence,
            action=action,
        )

        suggestion_response.additional_properties = d
        return suggestion_response

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
