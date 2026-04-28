from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TransferIn")


@_attrs_define
class TransferIn:
    """
    Attributes:
        from_person (str | Unset):  Default: ''.
        to_person (str | Unset):  Default: ''.
        transfer_reason (str | Unset):  Default: ''.
        location_change (str | Unset):  Default: ''.
    """

    from_person: str | Unset = ""
    to_person: str | Unset = ""
    transfer_reason: str | Unset = ""
    location_change: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from_person = self.from_person

        to_person = self.to_person

        transfer_reason = self.transfer_reason

        location_change = self.location_change

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if from_person is not UNSET:
            field_dict["from_person"] = from_person
        if to_person is not UNSET:
            field_dict["to_person"] = to_person
        if transfer_reason is not UNSET:
            field_dict["transfer_reason"] = transfer_reason
        if location_change is not UNSET:
            field_dict["location_change"] = location_change

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        from_person = d.pop("from_person", UNSET)

        to_person = d.pop("to_person", UNSET)

        transfer_reason = d.pop("transfer_reason", UNSET)

        location_change = d.pop("location_change", UNSET)

        transfer_in = cls(
            from_person=from_person,
            to_person=to_person,
            transfer_reason=transfer_reason,
            location_change=location_change,
        )

        transfer_in.additional_properties = d
        return transfer_in

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
