from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BodyHandleInteractionApiV1SlackInteractionsPost")


@_attrs_define
class BodyHandleInteractionApiV1SlackInteractionsPost:
    """
    Attributes:
        payload (str):
    """

    payload: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = self.payload

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "payload": payload,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        payload = d.pop("payload")

        body_handle_interaction_api_v1_slack_interactions_post = cls(
            payload=payload,
        )

        body_handle_interaction_api_v1_slack_interactions_post.additional_properties = d
        return body_handle_interaction_api_v1_slack_interactions_post

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
