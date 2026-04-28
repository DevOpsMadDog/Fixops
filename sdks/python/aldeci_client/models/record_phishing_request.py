from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordPhishingRequest")


@_attrs_define
class RecordPhishingRequest:
    """
    Attributes:
        campaign_name (str | Unset):  Default: ''.
        sent_at (None | str | Unset):
        clicked (int | Unset):  Default: 0.
        reported (int | Unset):  Default: 0.
        clicked_at (None | str | Unset):
        reported_at (None | str | Unset):
    """

    campaign_name: str | Unset = ""
    sent_at: None | str | Unset = UNSET
    clicked: int | Unset = 0
    reported: int | Unset = 0
    clicked_at: None | str | Unset = UNSET
    reported_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        campaign_name = self.campaign_name

        sent_at: None | str | Unset
        if isinstance(self.sent_at, Unset):
            sent_at = UNSET
        else:
            sent_at = self.sent_at

        clicked = self.clicked

        reported = self.reported

        clicked_at: None | str | Unset
        if isinstance(self.clicked_at, Unset):
            clicked_at = UNSET
        else:
            clicked_at = self.clicked_at

        reported_at: None | str | Unset
        if isinstance(self.reported_at, Unset):
            reported_at = UNSET
        else:
            reported_at = self.reported_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if campaign_name is not UNSET:
            field_dict["campaign_name"] = campaign_name
        if sent_at is not UNSET:
            field_dict["sent_at"] = sent_at
        if clicked is not UNSET:
            field_dict["clicked"] = clicked
        if reported is not UNSET:
            field_dict["reported"] = reported
        if clicked_at is not UNSET:
            field_dict["clicked_at"] = clicked_at
        if reported_at is not UNSET:
            field_dict["reported_at"] = reported_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        campaign_name = d.pop("campaign_name", UNSET)

        def _parse_sent_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sent_at = _parse_sent_at(d.pop("sent_at", UNSET))

        clicked = d.pop("clicked", UNSET)

        reported = d.pop("reported", UNSET)

        def _parse_clicked_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        clicked_at = _parse_clicked_at(d.pop("clicked_at", UNSET))

        def _parse_reported_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reported_at = _parse_reported_at(d.pop("reported_at", UNSET))

        record_phishing_request = cls(
            campaign_name=campaign_name,
            sent_at=sent_at,
            clicked=clicked,
            reported=reported,
            clicked_at=clicked_at,
            reported_at=reported_at,
        )

        record_phishing_request.additional_properties = d
        return record_phishing_request

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
