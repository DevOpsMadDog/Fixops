from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecipientItem")


@_attrs_define
class RecipientItem:
    """
    Attributes:
        recipient_type (str | Unset): ciso | soc | executive | all_staff | team | individual Default: 'individual'.
        recipient_id (None | str | Unset):
        recipient_email (None | str | Unset):
    """

    recipient_type: str | Unset = "individual"
    recipient_id: None | str | Unset = UNSET
    recipient_email: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        recipient_type = self.recipient_type

        recipient_id: None | str | Unset
        if isinstance(self.recipient_id, Unset):
            recipient_id = UNSET
        else:
            recipient_id = self.recipient_id

        recipient_email: None | str | Unset
        if isinstance(self.recipient_email, Unset):
            recipient_email = UNSET
        else:
            recipient_email = self.recipient_email

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if recipient_type is not UNSET:
            field_dict["recipient_type"] = recipient_type
        if recipient_id is not UNSET:
            field_dict["recipient_id"] = recipient_id
        if recipient_email is not UNSET:
            field_dict["recipient_email"] = recipient_email

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        recipient_type = d.pop("recipient_type", UNSET)

        def _parse_recipient_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        recipient_id = _parse_recipient_id(d.pop("recipient_id", UNSET))

        def _parse_recipient_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        recipient_email = _parse_recipient_email(d.pop("recipient_email", UNSET))

        recipient_item = cls(
            recipient_type=recipient_type,
            recipient_id=recipient_id,
            recipient_email=recipient_email,
        )

        recipient_item.additional_properties = d
        return recipient_item

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
