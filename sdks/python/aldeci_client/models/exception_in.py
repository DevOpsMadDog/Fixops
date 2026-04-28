from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExceptionIn")


@_attrs_define
class ExceptionIn:
    """
    Attributes:
        patch_id (str):
        asset_id (str):
        reason (str | Unset):  Default: ''.
        approved_by (str | Unset):  Default: ''.
        expires_at (None | str | Unset):
    """

    patch_id: str
    asset_id: str
    reason: str | Unset = ""
    approved_by: str | Unset = ""
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        patch_id = self.patch_id

        asset_id = self.asset_id

        reason = self.reason

        approved_by = self.approved_by

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "patch_id": patch_id,
                "asset_id": asset_id,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        patch_id = d.pop("patch_id")

        asset_id = d.pop("asset_id")

        reason = d.pop("reason", UNSET)

        approved_by = d.pop("approved_by", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        exception_in = cls(
            patch_id=patch_id,
            asset_id=asset_id,
            reason=reason,
            approved_by=approved_by,
            expires_at=expires_at,
        )

        exception_in.additional_properties = d
        return exception_in

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
