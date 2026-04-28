from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.canary_type import CanaryType
from ..types import UNSET, Unset

T = TypeVar("T", bound="CanaryToken")


@_attrs_define
class CanaryToken:
    """A deployed canary / honeypot asset.

    Attributes:
        type_ (CanaryType): Types of canary / honeypot deception assets.
        token_value (str):
        description (str):
        org_id (str):
        id (str | Unset):
        created_at (datetime.datetime | Unset):
        alert_count (int | Unset):  Default: 0.
        last_triggered_at (datetime.datetime | None | Unset):
        active (bool | Unset):  Default: True.
    """

    type_: CanaryType
    token_value: str
    description: str
    org_id: str
    id: str | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    alert_count: int | Unset = 0
    last_triggered_at: datetime.datetime | None | Unset = UNSET
    active: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        token_value = self.token_value

        description = self.description

        org_id = self.org_id

        id = self.id

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        alert_count = self.alert_count

        last_triggered_at: None | str | Unset
        if isinstance(self.last_triggered_at, Unset):
            last_triggered_at = UNSET
        elif isinstance(self.last_triggered_at, datetime.datetime):
            last_triggered_at = self.last_triggered_at.isoformat()
        else:
            last_triggered_at = self.last_triggered_at

        active = self.active

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "token_value": token_value,
                "description": description,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if alert_count is not UNSET:
            field_dict["alert_count"] = alert_count
        if last_triggered_at is not UNSET:
            field_dict["last_triggered_at"] = last_triggered_at
        if active is not UNSET:
            field_dict["active"] = active

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = CanaryType(d.pop("type"))

        token_value = d.pop("token_value")

        description = d.pop("description")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        alert_count = d.pop("alert_count", UNSET)

        def _parse_last_triggered_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_triggered_at_type_0 = isoparse(data)

                return last_triggered_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_triggered_at = _parse_last_triggered_at(d.pop("last_triggered_at", UNSET))

        active = d.pop("active", UNSET)

        canary_token = cls(
            type_=type_,
            token_value=token_value,
            description=description,
            org_id=org_id,
            id=id,
            created_at=created_at,
            alert_count=alert_count,
            last_triggered_at=last_triggered_at,
            active=active,
        )

        canary_token.additional_properties = d
        return canary_token

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
