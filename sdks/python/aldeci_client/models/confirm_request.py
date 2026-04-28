from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConfirmRequest")


@_attrs_define
class ConfirmRequest:
    """
    Attributes:
        rotated_by (str): Username/email of person who rotated
        new_secret_hash (None | str | Unset): SHA-256 hash of the new secret (not the value itself)
    """

    rotated_by: str
    new_secret_hash: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rotated_by = self.rotated_by

        new_secret_hash: None | str | Unset
        if isinstance(self.new_secret_hash, Unset):
            new_secret_hash = UNSET
        else:
            new_secret_hash = self.new_secret_hash

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rotated_by": rotated_by,
            }
        )
        if new_secret_hash is not UNSET:
            field_dict["new_secret_hash"] = new_secret_hash

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rotated_by = d.pop("rotated_by")

        def _parse_new_secret_hash(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        new_secret_hash = _parse_new_secret_hash(d.pop("new_secret_hash", UNSET))

        confirm_request = cls(
            rotated_by=rotated_by,
            new_secret_hash=new_secret_hash,
        )

        confirm_request.additional_properties = d
        return confirm_request

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
