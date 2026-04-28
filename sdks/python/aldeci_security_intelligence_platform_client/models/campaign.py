from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Campaign")


@_attrs_define
class Campaign:
    """Threat campaign linking actors to a coordinated attack effort.

    Attributes:
        id: Unique campaign identifier
        name: Campaign name
        threat_actor_id: ID of the responsible threat actor
        start_date: Campaign start date (ISO 8601)
        status: "active", "concluded", or "suspected"
        targets: Target sectors or org names
        iocs: Campaign-specific IOCs
        ttps: TTPs observed in this campaign

        Attributes:
            name (str):
            threat_actor_id (str):
            id (str | Unset):
            start_date (str | Unset):
            status (str | Unset):  Default: 'active'.
            targets (list[str] | Unset):
            iocs (list[str] | Unset):
            ttps (list[str] | Unset):
    """

    name: str
    threat_actor_id: str
    id: str | Unset = UNSET
    start_date: str | Unset = UNSET
    status: str | Unset = "active"
    targets: list[str] | Unset = UNSET
    iocs: list[str] | Unset = UNSET
    ttps: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        threat_actor_id = self.threat_actor_id

        id = self.id

        start_date = self.start_date

        status = self.status

        targets: list[str] | Unset = UNSET
        if not isinstance(self.targets, Unset):
            targets = self.targets

        iocs: list[str] | Unset = UNSET
        if not isinstance(self.iocs, Unset):
            iocs = self.iocs

        ttps: list[str] | Unset = UNSET
        if not isinstance(self.ttps, Unset):
            ttps = self.ttps

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "threat_actor_id": threat_actor_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if status is not UNSET:
            field_dict["status"] = status
        if targets is not UNSET:
            field_dict["targets"] = targets
        if iocs is not UNSET:
            field_dict["iocs"] = iocs
        if ttps is not UNSET:
            field_dict["ttps"] = ttps

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        threat_actor_id = d.pop("threat_actor_id")

        id = d.pop("id", UNSET)

        start_date = d.pop("start_date", UNSET)

        status = d.pop("status", UNSET)

        targets = cast(list[str], d.pop("targets", UNSET))

        iocs = cast(list[str], d.pop("iocs", UNSET))

        ttps = cast(list[str], d.pop("ttps", UNSET))

        campaign = cls(
            name=name,
            threat_actor_id=threat_actor_id,
            id=id,
            start_date=start_date,
            status=status,
            targets=targets,
            iocs=iocs,
            ttps=ttps,
        )

        campaign.additional_properties = d
        return campaign

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
