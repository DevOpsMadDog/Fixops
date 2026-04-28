from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CampaignResponse")


@_attrs_define
class CampaignResponse:
    """API response for a phishing campaign.

    Attributes:
        id (str):
        name (str):
        template_id (str):
        target_emails (list[str]):
        sent_count (int):
        opened_count (int):
        clicked_count (int):
        reported_count (int):
        started_at (str):
        ended_at (None | str):
        org_id (str):
    """

    id: str
    name: str
    template_id: str
    target_emails: list[str]
    sent_count: int
    opened_count: int
    clicked_count: int
    reported_count: int
    started_at: str
    ended_at: None | str
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        template_id = self.template_id

        target_emails = self.target_emails

        sent_count = self.sent_count

        opened_count = self.opened_count

        clicked_count = self.clicked_count

        reported_count = self.reported_count

        started_at = self.started_at

        ended_at: None | str
        ended_at = self.ended_at

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "template_id": template_id,
                "target_emails": target_emails,
                "sent_count": sent_count,
                "opened_count": opened_count,
                "clicked_count": clicked_count,
                "reported_count": reported_count,
                "started_at": started_at,
                "ended_at": ended_at,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        template_id = d.pop("template_id")

        target_emails = cast(list[str], d.pop("target_emails"))

        sent_count = d.pop("sent_count")

        opened_count = d.pop("opened_count")

        clicked_count = d.pop("clicked_count")

        reported_count = d.pop("reported_count")

        started_at = d.pop("started_at")

        def _parse_ended_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        ended_at = _parse_ended_at(d.pop("ended_at"))

        org_id = d.pop("org_id")

        campaign_response = cls(
            id=id,
            name=name,
            template_id=template_id,
            target_emails=target_emails,
            sent_count=sent_count,
            opened_count=opened_count,
            clicked_count=clicked_count,
            reported_count=reported_count,
            started_at=started_at,
            ended_at=ended_at,
            org_id=org_id,
        )

        campaign_response.additional_properties = d
        return campaign_response

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
