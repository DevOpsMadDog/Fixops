from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="PhishingClickRequest")


@_attrs_define
class PhishingClickRequest:
    """
    Attributes:
        campaign_id (str): Campaign ID from /phishing/launch
        user_id (str): User ID who clicked the link
    """

    campaign_id: str
    user_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        campaign_id = self.campaign_id

        user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "campaign_id": campaign_id,
                "user_id": user_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        campaign_id = d.pop("campaign_id")

        user_id = d.pop("user_id")

        phishing_click_request = cls(
            campaign_id=campaign_id,
            user_id=user_id,
        )

        phishing_click_request.additional_properties = d
        return phishing_click_request

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
