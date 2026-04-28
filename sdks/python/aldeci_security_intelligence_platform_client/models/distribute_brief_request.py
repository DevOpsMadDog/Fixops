from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.recipient_item import RecipientItem


T = TypeVar("T", bound="DistributeBriefRequest")


@_attrs_define
class DistributeBriefRequest:
    """
    Attributes:
        recipients (list[RecipientItem] | Unset): List of recipients to distribute to
    """

    recipients: list[RecipientItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        recipients: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.recipients, Unset):
            recipients = []
            for recipients_item_data in self.recipients:
                recipients_item = recipients_item_data.to_dict()
                recipients.append(recipients_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if recipients is not UNSET:
            field_dict["recipients"] = recipients

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.recipient_item import RecipientItem

        d = dict(src_dict)
        _recipients = d.pop("recipients", UNSET)
        recipients: list[RecipientItem] | Unset = UNSET
        if _recipients is not UNSET:
            recipients = []
            for recipients_item_data in _recipients:
                recipients_item = RecipientItem.from_dict(recipients_item_data)

                recipients.append(recipients_item)

        distribute_brief_request = cls(
            recipients=recipients,
        )

        distribute_brief_request.additional_properties = d
        return distribute_brief_request

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
