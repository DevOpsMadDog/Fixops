from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatCreateReq")


@_attrs_define
class ThreatCreateReq:
    """
    Attributes:
        org_id (str):
        workload_id (str):
        threat_type (str):
        severity (str | Unset):  Default: 'medium'.
        detection_source (str | Unset):  Default: 'runtime'.
        detected_at (None | str | Unset):
    """

    org_id: str
    workload_id: str
    threat_type: str
    severity: str | Unset = "medium"
    detection_source: str | Unset = "runtime"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        workload_id = self.workload_id

        threat_type = self.threat_type

        severity = self.severity

        detection_source = self.detection_source

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "workload_id": workload_id,
                "threat_type": threat_type,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if detection_source is not UNSET:
            field_dict["detection_source"] = detection_source
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        workload_id = d.pop("workload_id")

        threat_type = d.pop("threat_type")

        severity = d.pop("severity", UNSET)

        detection_source = d.pop("detection_source", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        threat_create_req = cls(
            org_id=org_id,
            workload_id=workload_id,
            threat_type=threat_type,
            severity=severity,
            detection_source=detection_source,
            detected_at=detected_at,
        )

        threat_create_req.additional_properties = d
        return threat_create_req

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
