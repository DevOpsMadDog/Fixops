from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sla_policy_deadlines import SLAPolicyDeadlines


T = TypeVar("T", bound="SLAPolicy")


@_attrs_define
class SLAPolicy:
    """
    Attributes:
        name (str):
        org_id (str):
        id (str | Unset):
        deadlines (SLAPolicyDeadlines | Unset): Deadline in hours per severity
        created_at (datetime.datetime | Unset):
    """

    name: str
    org_id: str
    id: str | Unset = UNSET
    deadlines: SLAPolicyDeadlines | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        org_id = self.org_id

        id = self.id

        deadlines: dict[str, Any] | Unset = UNSET
        if not isinstance(self.deadlines, Unset):
            deadlines = self.deadlines.to_dict()

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if deadlines is not UNSET:
            field_dict["deadlines"] = deadlines
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sla_policy_deadlines import SLAPolicyDeadlines

        d = dict(src_dict)
        name = d.pop("name")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _deadlines = d.pop("deadlines", UNSET)
        deadlines: SLAPolicyDeadlines | Unset
        if isinstance(_deadlines, Unset):
            deadlines = UNSET
        else:
            deadlines = SLAPolicyDeadlines.from_dict(_deadlines)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        sla_policy = cls(
            name=name,
            org_id=org_id,
            id=id,
            deadlines=deadlines,
            created_at=created_at,
        )

        sla_policy.additional_properties = d
        return sla_policy

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
