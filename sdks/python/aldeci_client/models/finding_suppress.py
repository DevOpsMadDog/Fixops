from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="FindingSuppress")


@_attrs_define
class FindingSuppress:
    """
    Attributes:
        org_id (str):
        reason (str):
        suppressed_by (str):
        expires_at (str):
    """

    org_id: str
    reason: str
    suppressed_by: str
    expires_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        reason = self.reason

        suppressed_by = self.suppressed_by

        expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "reason": reason,
                "suppressed_by": suppressed_by,
                "expires_at": expires_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        reason = d.pop("reason")

        suppressed_by = d.pop("suppressed_by")

        expires_at = d.pop("expires_at")

        finding_suppress = cls(
            org_id=org_id,
            reason=reason,
            suppressed_by=suppressed_by,
            expires_at=expires_at,
        )

        finding_suppress.additional_properties = d
        return finding_suppress

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
