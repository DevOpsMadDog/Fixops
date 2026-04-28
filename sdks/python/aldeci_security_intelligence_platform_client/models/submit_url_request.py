from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubmitUrlRequest")


@_attrs_define
class SubmitUrlRequest:
    """
    Attributes:
        url (str):
        submission_source (str | Unset):  Default: 'automated'.
        submitted_at (None | str | Unset):
    """

    url: str
    submission_source: str | Unset = "automated"
    submitted_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        url = self.url

        submission_source = self.submission_source

        submitted_at: None | str | Unset
        if isinstance(self.submitted_at, Unset):
            submitted_at = UNSET
        else:
            submitted_at = self.submitted_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "url": url,
            }
        )
        if submission_source is not UNSET:
            field_dict["submission_source"] = submission_source
        if submitted_at is not UNSET:
            field_dict["submitted_at"] = submitted_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        url = d.pop("url")

        submission_source = d.pop("submission_source", UNSET)

        def _parse_submitted_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        submitted_at = _parse_submitted_at(d.pop("submitted_at", UNSET))

        submit_url_request = cls(
            url=url,
            submission_source=submission_source,
            submitted_at=submitted_at,
        )

        submit_url_request.additional_properties = d
        return submit_url_request

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
