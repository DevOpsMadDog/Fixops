from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.classification_level import ClassificationLevel
from ..types import UNSET, Unset

T = TypeVar("T", bound="UpgradeRequest")


@_attrs_define
class UpgradeRequest:
    """
    Attributes:
        new_level (ClassificationLevel):
        reason (None | str | Unset):
        changed_by (str | Unset):  Default: 'api-user'.
    """

    new_level: ClassificationLevel
    reason: None | str | Unset = UNSET
    changed_by: str | Unset = "api-user"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        new_level = self.new_level.value

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        changed_by = self.changed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "new_level": new_level,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason
        if changed_by is not UNSET:
            field_dict["changed_by"] = changed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_level = ClassificationLevel(d.pop("new_level"))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        changed_by = d.pop("changed_by", UNSET)

        upgrade_request = cls(
            new_level=new_level,
            reason=reason,
            changed_by=changed_by,
        )

        upgrade_request.additional_properties = d
        return upgrade_request

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
