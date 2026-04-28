from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordSimulationRequest")


@_attrs_define
class RecordSimulationRequest:
    """
    Attributes:
        campaign_name (str):
        simulation_type (str):
        sent_count (int):
        target_department (str | Unset):  Default: ''.
        opened (int | Unset):  Default: 0.
        clicked (int | Unset):  Default: 0.
        reported (int | Unset):  Default: 0.
        started_at (None | str | Unset):
    """

    campaign_name: str
    simulation_type: str
    sent_count: int
    target_department: str | Unset = ""
    opened: int | Unset = 0
    clicked: int | Unset = 0
    reported: int | Unset = 0
    started_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        campaign_name = self.campaign_name

        simulation_type = self.simulation_type

        sent_count = self.sent_count

        target_department = self.target_department

        opened = self.opened

        clicked = self.clicked

        reported = self.reported

        started_at: None | str | Unset
        if isinstance(self.started_at, Unset):
            started_at = UNSET
        else:
            started_at = self.started_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "campaign_name": campaign_name,
                "simulation_type": simulation_type,
                "sent_count": sent_count,
            }
        )
        if target_department is not UNSET:
            field_dict["target_department"] = target_department
        if opened is not UNSET:
            field_dict["opened"] = opened
        if clicked is not UNSET:
            field_dict["clicked"] = clicked
        if reported is not UNSET:
            field_dict["reported"] = reported
        if started_at is not UNSET:
            field_dict["started_at"] = started_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        campaign_name = d.pop("campaign_name")

        simulation_type = d.pop("simulation_type")

        sent_count = d.pop("sent_count")

        target_department = d.pop("target_department", UNSET)

        opened = d.pop("opened", UNSET)

        clicked = d.pop("clicked", UNSET)

        reported = d.pop("reported", UNSET)

        def _parse_started_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        started_at = _parse_started_at(d.pop("started_at", UNSET))

        record_simulation_request = cls(
            campaign_name=campaign_name,
            simulation_type=simulation_type,
            sent_count=sent_count,
            target_department=target_department,
            opened=opened,
            clicked=clicked,
            reported=reported,
            started_at=started_at,
        )

        record_simulation_request.additional_properties = d
        return record_simulation_request

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
