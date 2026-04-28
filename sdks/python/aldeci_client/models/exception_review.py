from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExceptionReview")


@_attrs_define
class ExceptionReview:
    """
    Attributes:
        action (str):
        reviewer (str):
        notes (str | Unset):  Default: ''.
        new_expiry (None | str | Unset):
    """

    action: str
    reviewer: str
    notes: str | Unset = ""
    new_expiry: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action = self.action

        reviewer = self.reviewer

        notes = self.notes

        new_expiry: None | str | Unset
        if isinstance(self.new_expiry, Unset):
            new_expiry = UNSET
        else:
            new_expiry = self.new_expiry

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action": action,
                "reviewer": reviewer,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes
        if new_expiry is not UNSET:
            field_dict["new_expiry"] = new_expiry

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = d.pop("action")

        reviewer = d.pop("reviewer")

        notes = d.pop("notes", UNSET)

        def _parse_new_expiry(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        new_expiry = _parse_new_expiry(d.pop("new_expiry", UNSET))

        exception_review = cls(
            action=action,
            reviewer=reviewer,
            notes=notes,
            new_expiry=new_expiry,
        )

        exception_review.additional_properties = d
        return exception_review

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
