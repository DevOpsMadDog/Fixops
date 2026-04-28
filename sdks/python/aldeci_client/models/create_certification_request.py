from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCertificationRequest")


@_attrs_define
class CreateCertificationRequest:
    """
    Attributes:
        reviewer (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'pending'.
        access_level (str | Unset):  Default: ''.
        certified_at (None | str | Unset):
        next_review (None | str | Unset):
    """

    reviewer: str | Unset = ""
    status: str | Unset = "pending"
    access_level: str | Unset = ""
    certified_at: None | str | Unset = UNSET
    next_review: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        reviewer = self.reviewer

        status = self.status

        access_level = self.access_level

        certified_at: None | str | Unset
        if isinstance(self.certified_at, Unset):
            certified_at = UNSET
        else:
            certified_at = self.certified_at

        next_review: None | str | Unset
        if isinstance(self.next_review, Unset):
            next_review = UNSET
        else:
            next_review = self.next_review

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if reviewer is not UNSET:
            field_dict["reviewer"] = reviewer
        if status is not UNSET:
            field_dict["status"] = status
        if access_level is not UNSET:
            field_dict["access_level"] = access_level
        if certified_at is not UNSET:
            field_dict["certified_at"] = certified_at
        if next_review is not UNSET:
            field_dict["next_review"] = next_review

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        reviewer = d.pop("reviewer", UNSET)

        status = d.pop("status", UNSET)

        access_level = d.pop("access_level", UNSET)

        def _parse_certified_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        certified_at = _parse_certified_at(d.pop("certified_at", UNSET))

        def _parse_next_review(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_review = _parse_next_review(d.pop("next_review", UNSET))

        create_certification_request = cls(
            reviewer=reviewer,
            status=status,
            access_level=access_level,
            certified_at=certified_at,
            next_review=next_review,
        )

        create_certification_request.additional_properties = d
        return create_certification_request

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
