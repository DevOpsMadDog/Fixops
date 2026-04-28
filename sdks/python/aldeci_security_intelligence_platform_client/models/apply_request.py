from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ApplyRequest")


@_attrs_define
class ApplyRequest:
    """
    Attributes:
        dry_run (bool | Unset):  Default: False.
        applied_by (str | Unset):  Default: 'system'.
        require_verified (bool | Unset):  Default: True.
    """

    dry_run: bool | Unset = False
    applied_by: str | Unset = "system"
    require_verified: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dry_run = self.dry_run

        applied_by = self.applied_by

        require_verified = self.require_verified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dry_run is not UNSET:
            field_dict["dry_run"] = dry_run
        if applied_by is not UNSET:
            field_dict["applied_by"] = applied_by
        if require_verified is not UNSET:
            field_dict["require_verified"] = require_verified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dry_run = d.pop("dry_run", UNSET)

        applied_by = d.pop("applied_by", UNSET)

        require_verified = d.pop("require_verified", UNSET)

        apply_request = cls(
            dry_run=dry_run,
            applied_by=applied_by,
            require_verified=require_verified,
        )

        apply_request.additional_properties = d
        return apply_request

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
