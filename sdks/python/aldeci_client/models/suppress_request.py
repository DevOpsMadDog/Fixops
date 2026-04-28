from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SuppressRequest")


@_attrs_define
class SuppressRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        suppressed_by (str): Who suppressed
        reason (str): Suppression reason
        expires_at (str | Unset): ISO-8601 expiry (optional) Default: ''.
    """

    org_id: str
    suppressed_by: str
    reason: str
    expires_at: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        suppressed_by = self.suppressed_by

        reason = self.reason

        expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "suppressed_by": suppressed_by,
                "reason": reason,
            }
        )
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        suppressed_by = d.pop("suppressed_by")

        reason = d.pop("reason")

        expires_at = d.pop("expires_at", UNSET)

        suppress_request = cls(
            org_id=org_id,
            suppressed_by=suppressed_by,
            reason=reason,
            expires_at=expires_at,
        )

        suppress_request.additional_properties = d
        return suppress_request

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
