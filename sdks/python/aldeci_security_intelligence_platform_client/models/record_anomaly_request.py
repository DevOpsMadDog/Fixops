from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAnomalyRequest")


@_attrs_define
class RecordAnomalyRequest:
    """
    Attributes:
        org_id (str | Unset): Organisation ID Default: 'default'.
        anomaly_type (str | Unset): Anomaly type Default: 'unusual_api'.
        severity (str | Unset): Severity: critical/high/medium/low Default: 'medium'.
        account_id (str | Unset): Cloud account ID Default: ''.
        confidence_score (float | Unset): Confidence 0-100 Default: 0.0.
        affected_resources (list[str] | Unset): Affected resource IDs
        status (str | Unset): Anomaly status Default: 'open'.
        detected_at (None | str | Unset): ISO-8601 detection timestamp
    """

    org_id: str | Unset = "default"
    anomaly_type: str | Unset = "unusual_api"
    severity: str | Unset = "medium"
    account_id: str | Unset = ""
    confidence_score: float | Unset = 0.0
    affected_resources: list[str] | Unset = UNSET
    status: str | Unset = "open"
    detected_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        anomaly_type = self.anomaly_type

        severity = self.severity

        account_id = self.account_id

        confidence_score = self.confidence_score

        affected_resources: list[str] | Unset = UNSET
        if not isinstance(self.affected_resources, Unset):
            affected_resources = self.affected_resources

        status = self.status

        detected_at: None | str | Unset
        if isinstance(self.detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = self.detected_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if anomaly_type is not UNSET:
            field_dict["anomaly_type"] = anomaly_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if affected_resources is not UNSET:
            field_dict["affected_resources"] = affected_resources
        if status is not UNSET:
            field_dict["status"] = status
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        anomaly_type = d.pop("anomaly_type", UNSET)

        severity = d.pop("severity", UNSET)

        account_id = d.pop("account_id", UNSET)

        confidence_score = d.pop("confidence_score", UNSET)

        affected_resources = cast(list[str], d.pop("affected_resources", UNSET))

        status = d.pop("status", UNSET)

        def _parse_detected_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_at = _parse_detected_at(d.pop("detected_at", UNSET))

        record_anomaly_request = cls(
            org_id=org_id,
            anomaly_type=anomaly_type,
            severity=severity,
            account_id=account_id,
            confidence_score=confidence_score,
            affected_resources=affected_resources,
            status=status,
            detected_at=detected_at,
        )

        record_anomaly_request.additional_properties = d
        return record_anomaly_request

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
