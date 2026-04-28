from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeploymentRecord")


@_attrs_define
class DeploymentRecord:
    """Request body for recording a deployment.

    Attributes:
        is_failure (bool):
        deployed_at (datetime.datetime | None | Unset):
        notes (str | Unset):  Default: ''.
    """

    is_failure: bool
    deployed_at: datetime.datetime | None | Unset = UNSET
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        is_failure = self.is_failure

        deployed_at: None | str | Unset
        if isinstance(self.deployed_at, Unset):
            deployed_at = UNSET
        elif isinstance(self.deployed_at, datetime.datetime):
            deployed_at = self.deployed_at.isoformat()
        else:
            deployed_at = self.deployed_at

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "is_failure": is_failure,
            }
        )
        if deployed_at is not UNSET:
            field_dict["deployed_at"] = deployed_at
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        is_failure = d.pop("is_failure")

        def _parse_deployed_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                deployed_at_type_0 = isoparse(data)

                return deployed_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        deployed_at = _parse_deployed_at(d.pop("deployed_at", UNSET))

        notes = d.pop("notes", UNSET)

        deployment_record = cls(
            is_failure=is_failure,
            deployed_at=deployed_at,
            notes=notes,
        )

        deployment_record.additional_properties = d
        return deployment_record

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
