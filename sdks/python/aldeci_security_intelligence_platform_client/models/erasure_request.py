from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.erasure_status import ErasureStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="ErasureRequest")


@_attrs_define
class ErasureRequest:
    """GDPR right-to-erasure request for a data subject.

    Attributes:
        subject_email (str):
        id (str | Unset):
        requested_at (datetime.datetime | Unset):
        completed_at (datetime.datetime | None | Unset):
        status (ErasureStatus | Unset): Status of a GDPR erasure request.
        categories_erased (list[str] | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    subject_email: str
    id: str | Unset = UNSET
    requested_at: datetime.datetime | Unset = UNSET
    completed_at: datetime.datetime | None | Unset = UNSET
    status: ErasureStatus | Unset = UNSET
    categories_erased: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject_email = self.subject_email

        id = self.id

        requested_at: str | Unset = UNSET
        if not isinstance(self.requested_at, Unset):
            requested_at = self.requested_at.isoformat()

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        categories_erased: list[str] | Unset = UNSET
        if not isinstance(self.categories_erased, Unset):
            categories_erased = self.categories_erased

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject_email": subject_email,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if requested_at is not UNSET:
            field_dict["requested_at"] = requested_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if status is not UNSET:
            field_dict["status"] = status
        if categories_erased is not UNSET:
            field_dict["categories_erased"] = categories_erased
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subject_email = d.pop("subject_email")

        id = d.pop("id", UNSET)

        _requested_at = d.pop("requested_at", UNSET)
        requested_at: datetime.datetime | Unset
        if isinstance(_requested_at, Unset):
            requested_at = UNSET
        else:
            requested_at = isoparse(_requested_at)

        def _parse_completed_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                completed_at_type_0 = isoparse(data)

                return completed_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        _status = d.pop("status", UNSET)
        status: ErasureStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = ErasureStatus(_status)

        categories_erased = cast(list[str], d.pop("categories_erased", UNSET))

        org_id = d.pop("org_id", UNSET)

        erasure_request = cls(
            subject_email=subject_email,
            id=id,
            requested_at=requested_at,
            completed_at=completed_at,
            status=status,
            categories_erased=categories_erased,
            org_id=org_id,
        )

        erasure_request.additional_properties = d
        return erasure_request

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
