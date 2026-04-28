from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RotateRequest")


@_attrs_define
class RotateRequest:
    """Request body for /{id}/rotate endpoint.

    Attributes:
        rotated_by (str): Email/username of person who rotated the secret
        new_key_prefix (None | str | Unset): First chars of the replacement key (optional)
    """

    rotated_by: str
    new_key_prefix: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rotated_by = self.rotated_by

        new_key_prefix: None | str | Unset
        if isinstance(self.new_key_prefix, Unset):
            new_key_prefix = UNSET
        else:
            new_key_prefix = self.new_key_prefix

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rotated_by": rotated_by,
            }
        )
        if new_key_prefix is not UNSET:
            field_dict["new_key_prefix"] = new_key_prefix

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        rotated_by = d.pop("rotated_by")

        def _parse_new_key_prefix(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        new_key_prefix = _parse_new_key_prefix(d.pop("new_key_prefix", UNSET))

        rotate_request = cls(
            rotated_by=rotated_by,
            new_key_prefix=new_key_prefix,
        )

        rotate_request.additional_properties = d
        return rotate_request

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
