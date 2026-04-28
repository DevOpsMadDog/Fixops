from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAttackRequest")


@_attrs_define
class RecordAttackRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        resource_id (str): Protected resource UUID
        attack_type (str): volumetric | protocol | application | slowloris | amplification
        source_ips (list[str] | Unset): List of attacking source IPs
        peak_gbps (float | Unset): Peak attack volume in Gbps Default: 0.0.
        duration_seconds (int | Unset): Attack duration in seconds Default: 0.
        status (str | Unset): detected | mitigating | mitigated Default: 'detected'.
    """

    org_id: str
    resource_id: str
    attack_type: str
    source_ips: list[str] | Unset = UNSET
    peak_gbps: float | Unset = 0.0
    duration_seconds: int | Unset = 0
    status: str | Unset = "detected"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        resource_id = self.resource_id

        attack_type = self.attack_type

        source_ips: list[str] | Unset = UNSET
        if not isinstance(self.source_ips, Unset):
            source_ips = self.source_ips

        peak_gbps = self.peak_gbps

        duration_seconds = self.duration_seconds

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "resource_id": resource_id,
                "attack_type": attack_type,
            }
        )
        if source_ips is not UNSET:
            field_dict["source_ips"] = source_ips
        if peak_gbps is not UNSET:
            field_dict["peak_gbps"] = peak_gbps
        if duration_seconds is not UNSET:
            field_dict["duration_seconds"] = duration_seconds
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        resource_id = d.pop("resource_id")

        attack_type = d.pop("attack_type")

        source_ips = cast(list[str], d.pop("source_ips", UNSET))

        peak_gbps = d.pop("peak_gbps", UNSET)

        duration_seconds = d.pop("duration_seconds", UNSET)

        status = d.pop("status", UNSET)

        record_attack_request = cls(
            org_id=org_id,
            resource_id=resource_id,
            attack_type=attack_type,
            source_ips=source_ips,
            peak_gbps=peak_gbps,
            duration_seconds=duration_seconds,
            status=status,
        )

        record_attack_request.additional_properties = d
        return record_attack_request

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
