from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompleteRequest")


@_attrs_define
class CompleteRequest:
    """
    Attributes:
        actor_id (str):
        actor_name (str):
        implementation_notes (None | str | Unset):
        post_implementation_review (None | str | Unset):
    """

    actor_id: str
    actor_name: str
    implementation_notes: None | str | Unset = UNSET
    post_implementation_review: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actor_id = self.actor_id

        actor_name = self.actor_name

        implementation_notes: None | str | Unset
        if isinstance(self.implementation_notes, Unset):
            implementation_notes = UNSET
        else:
            implementation_notes = self.implementation_notes

        post_implementation_review: None | str | Unset
        if isinstance(self.post_implementation_review, Unset):
            post_implementation_review = UNSET
        else:
            post_implementation_review = self.post_implementation_review

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "actor_id": actor_id,
                "actor_name": actor_name,
            }
        )
        if implementation_notes is not UNSET:
            field_dict["implementation_notes"] = implementation_notes
        if post_implementation_review is not UNSET:
            field_dict["post_implementation_review"] = post_implementation_review

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        actor_id = d.pop("actor_id")

        actor_name = d.pop("actor_name")

        def _parse_implementation_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        implementation_notes = _parse_implementation_notes(d.pop("implementation_notes", UNSET))

        def _parse_post_implementation_review(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        post_implementation_review = _parse_post_implementation_review(d.pop("post_implementation_review", UNSET))

        complete_request = cls(
            actor_id=actor_id,
            actor_name=actor_name,
            implementation_notes=implementation_notes,
            post_implementation_review=post_implementation_review,
        )

        complete_request.additional_properties = d
        return complete_request

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
