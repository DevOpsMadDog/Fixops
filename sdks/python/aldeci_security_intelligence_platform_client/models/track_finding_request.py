from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrackFindingRequest")


@_attrs_define
class TrackFindingRequest:
    """
    Attributes:
        finding_id (str):
        severity (str):
        policy_id (None | str | Unset):
        discovered_at (datetime.datetime | None | Unset):
    """

    finding_id: str
    severity: str
    policy_id: None | str | Unset = UNSET
    discovered_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        severity = self.severity

        policy_id: None | str | Unset
        if isinstance(self.policy_id, Unset):
            policy_id = UNSET
        else:
            policy_id = self.policy_id

        discovered_at: None | str | Unset
        if isinstance(self.discovered_at, Unset):
            discovered_at = UNSET
        elif isinstance(self.discovered_at, datetime.datetime):
            discovered_at = self.discovered_at.isoformat()
        else:
            discovered_at = self.discovered_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "severity": severity,
            }
        )
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        severity = d.pop("severity")

        def _parse_policy_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_id = _parse_policy_id(d.pop("policy_id", UNSET))

        def _parse_discovered_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                discovered_at_type_0 = isoparse(data)

                return discovered_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        discovered_at = _parse_discovered_at(d.pop("discovered_at", UNSET))

        track_finding_request = cls(
            finding_id=finding_id,
            severity=severity,
            policy_id=policy_id,
            discovered_at=discovered_at,
        )

        track_finding_request.additional_properties = d
        return track_finding_request

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
