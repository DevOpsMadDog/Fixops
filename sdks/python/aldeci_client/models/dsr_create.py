from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DSRCreate")


@_attrs_define
class DSRCreate:
    """
    Attributes:
        subject_email (str):
        request_type (str | Unset):  Default: 'access'.
        subject_name (str | Unset):  Default: ''.
        identity_verified (bool | Unset):  Default: False.
        regulation (str | Unset):  Default: 'gdpr'.
        notes (str | Unset):  Default: ''.
    """

    subject_email: str
    request_type: str | Unset = "access"
    subject_name: str | Unset = ""
    identity_verified: bool | Unset = False
    regulation: str | Unset = "gdpr"
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        subject_email = self.subject_email

        request_type = self.request_type

        subject_name = self.subject_name

        identity_verified = self.identity_verified

        regulation = self.regulation

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "subject_email": subject_email,
            }
        )
        if request_type is not UNSET:
            field_dict["request_type"] = request_type
        if subject_name is not UNSET:
            field_dict["subject_name"] = subject_name
        if identity_verified is not UNSET:
            field_dict["identity_verified"] = identity_verified
        if regulation is not UNSET:
            field_dict["regulation"] = regulation
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        subject_email = d.pop("subject_email")

        request_type = d.pop("request_type", UNSET)

        subject_name = d.pop("subject_name", UNSET)

        identity_verified = d.pop("identity_verified", UNSET)

        regulation = d.pop("regulation", UNSET)

        notes = d.pop("notes", UNSET)

        dsr_create = cls(
            subject_email=subject_email,
            request_type=request_type,
            subject_name=subject_name,
            identity_verified=identity_verified,
            regulation=regulation,
            notes=notes,
        )

        dsr_create.additional_properties = d
        return dsr_create

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
