from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.classification_level import ClassificationLevel

T = TypeVar("T", bound="DowngradeRequest")


@_attrs_define
class DowngradeRequest:
    """
    Attributes:
        new_level (ClassificationLevel):
        approval_id (str):
        reason (str):
        changed_by (str):
    """

    new_level: ClassificationLevel
    approval_id: str
    reason: str
    changed_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        new_level = self.new_level.value

        approval_id = self.approval_id

        reason = self.reason

        changed_by = self.changed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "new_level": new_level,
                "approval_id": approval_id,
                "reason": reason,
                "changed_by": changed_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_level = ClassificationLevel(d.pop("new_level"))

        approval_id = d.pop("approval_id")

        reason = d.pop("reason")

        changed_by = d.pop("changed_by")

        downgrade_request = cls(
            new_level=new_level,
            approval_id=approval_id,
            reason=reason,
            changed_by=changed_by,
        )

        downgrade_request.additional_properties = d
        return downgrade_request

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
