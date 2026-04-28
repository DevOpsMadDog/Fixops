from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RetentionPolicyIn")


@_attrs_define
class RetentionPolicyIn:
    """Retention policy upsert payload.

    Attributes:
        archive_after_days (int | Unset):  Default: 90.
        delete_after_days (int | Unset):  Default: 365.
        legal_hold_actor_ids (list[str] | Unset):
    """

    archive_after_days: int | Unset = 90
    delete_after_days: int | Unset = 365
    legal_hold_actor_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        archive_after_days = self.archive_after_days

        delete_after_days = self.delete_after_days

        legal_hold_actor_ids: list[str] | Unset = UNSET
        if not isinstance(self.legal_hold_actor_ids, Unset):
            legal_hold_actor_ids = self.legal_hold_actor_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if archive_after_days is not UNSET:
            field_dict["archive_after_days"] = archive_after_days
        if delete_after_days is not UNSET:
            field_dict["delete_after_days"] = delete_after_days
        if legal_hold_actor_ids is not UNSET:
            field_dict["legal_hold_actor_ids"] = legal_hold_actor_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        archive_after_days = d.pop("archive_after_days", UNSET)

        delete_after_days = d.pop("delete_after_days", UNSET)

        legal_hold_actor_ids = cast(list[str], d.pop("legal_hold_actor_ids", UNSET))

        retention_policy_in = cls(
            archive_after_days=archive_after_days,
            delete_after_days=delete_after_days,
            legal_hold_actor_ids=legal_hold_actor_ids,
        )

        retention_policy_in.additional_properties = d
        return retention_policy_in

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
