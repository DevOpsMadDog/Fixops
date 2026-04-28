from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateCampaignRequest")


@_attrs_define
class CreateCampaignRequest:
    """
    Attributes:
        title (str): Campaign title
        campaign_type (str | Unset): phishing_sim | training | quiz | newsletter | video | tabletop Default: 'training'.
        campaign_status (str | Unset): draft | active | completed | paused | cancelled Default: 'draft'.
        target_department (None | str | Unset):
        target_count (int | None | Unset):  Default: 0.
        start_date (None | str | Unset):
        end_date (None | str | Unset):
        created_by (None | str | Unset):
    """

    title: str
    campaign_type: str | Unset = "training"
    campaign_status: str | Unset = "draft"
    target_department: None | str | Unset = UNSET
    target_count: int | None | Unset = 0
    start_date: None | str | Unset = UNSET
    end_date: None | str | Unset = UNSET
    created_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        campaign_type = self.campaign_type

        campaign_status = self.campaign_status

        target_department: None | str | Unset
        if isinstance(self.target_department, Unset):
            target_department = UNSET
        else:
            target_department = self.target_department

        target_count: int | None | Unset
        if isinstance(self.target_count, Unset):
            target_count = UNSET
        else:
            target_count = self.target_count

        start_date: None | str | Unset
        if isinstance(self.start_date, Unset):
            start_date = UNSET
        else:
            start_date = self.start_date

        end_date: None | str | Unset
        if isinstance(self.end_date, Unset):
            end_date = UNSET
        else:
            end_date = self.end_date

        created_by: None | str | Unset
        if isinstance(self.created_by, Unset):
            created_by = UNSET
        else:
            created_by = self.created_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if campaign_type is not UNSET:
            field_dict["campaign_type"] = campaign_type
        if campaign_status is not UNSET:
            field_dict["campaign_status"] = campaign_status
        if target_department is not UNSET:
            field_dict["target_department"] = target_department
        if target_count is not UNSET:
            field_dict["target_count"] = target_count
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if end_date is not UNSET:
            field_dict["end_date"] = end_date
        if created_by is not UNSET:
            field_dict["created_by"] = created_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        campaign_type = d.pop("campaign_type", UNSET)

        campaign_status = d.pop("campaign_status", UNSET)

        def _parse_target_department(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_department = _parse_target_department(d.pop("target_department", UNSET))

        def _parse_target_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        target_count = _parse_target_count(d.pop("target_count", UNSET))

        def _parse_start_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        start_date = _parse_start_date(d.pop("start_date", UNSET))

        def _parse_end_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        end_date = _parse_end_date(d.pop("end_date", UNSET))

        def _parse_created_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        created_by = _parse_created_by(d.pop("created_by", UNSET))

        create_campaign_request = cls(
            title=title,
            campaign_type=campaign_type,
            campaign_status=campaign_status,
            target_department=target_department,
            target_count=target_count,
            start_date=start_date,
            end_date=end_date,
            created_by=created_by,
        )

        create_campaign_request.additional_properties = d
        return create_campaign_request

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
