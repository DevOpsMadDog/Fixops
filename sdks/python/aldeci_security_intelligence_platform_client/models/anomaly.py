from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.anomaly_severity import AnomalySeverity
from ..models.anomaly_type import AnomalyType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.anomaly_context import AnomalyContext


T = TypeVar("T", bound="Anomaly")


@_attrs_define
class Anomaly:
    """A detected anomaly event.

    Attributes:
        type_ (AnomalyType): Types of detectable anomalies.
        metric_name (str):
        expected_value (float):
        actual_value (float):
        deviation_pct (float):
        severity (AnomalySeverity): Severity levels for detected anomalies.
        org_id (str):
        id (str | Unset):
        detected_at (datetime.datetime | Unset):
        context (AnomalyContext | Unset):
        acknowledged (bool | Unset):  Default: False.
        acknowledged_at (datetime.datetime | None | Unset):
    """

    type_: AnomalyType
    metric_name: str
    expected_value: float
    actual_value: float
    deviation_pct: float
    severity: AnomalySeverity
    org_id: str
    id: str | Unset = UNSET
    detected_at: datetime.datetime | Unset = UNSET
    context: AnomalyContext | Unset = UNSET
    acknowledged: bool | Unset = False
    acknowledged_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        metric_name = self.metric_name

        expected_value = self.expected_value

        actual_value = self.actual_value

        deviation_pct = self.deviation_pct

        severity = self.severity.value

        org_id = self.org_id

        id = self.id

        detected_at: str | Unset = UNSET
        if not isinstance(self.detected_at, Unset):
            detected_at = self.detected_at.isoformat()

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        acknowledged = self.acknowledged

        acknowledged_at: None | str | Unset
        if isinstance(self.acknowledged_at, Unset):
            acknowledged_at = UNSET
        elif isinstance(self.acknowledged_at, datetime.datetime):
            acknowledged_at = self.acknowledged_at.isoformat()
        else:
            acknowledged_at = self.acknowledged_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "metric_name": metric_name,
                "expected_value": expected_value,
                "actual_value": actual_value,
                "deviation_pct": deviation_pct,
                "severity": severity,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at
        if context is not UNSET:
            field_dict["context"] = context
        if acknowledged is not UNSET:
            field_dict["acknowledged"] = acknowledged
        if acknowledged_at is not UNSET:
            field_dict["acknowledged_at"] = acknowledged_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.anomaly_context import AnomalyContext

        d = dict(src_dict)
        type_ = AnomalyType(d.pop("type"))

        metric_name = d.pop("metric_name")

        expected_value = d.pop("expected_value")

        actual_value = d.pop("actual_value")

        deviation_pct = d.pop("deviation_pct")

        severity = AnomalySeverity(d.pop("severity"))

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _detected_at = d.pop("detected_at", UNSET)
        detected_at: datetime.datetime | Unset
        if isinstance(_detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = isoparse(_detected_at)

        _context = d.pop("context", UNSET)
        context: AnomalyContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = AnomalyContext.from_dict(_context)

        acknowledged = d.pop("acknowledged", UNSET)

        def _parse_acknowledged_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                acknowledged_at_type_0 = isoparse(data)

                return acknowledged_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        acknowledged_at = _parse_acknowledged_at(d.pop("acknowledged_at", UNSET))

        anomaly = cls(
            type_=type_,
            metric_name=metric_name,
            expected_value=expected_value,
            actual_value=actual_value,
            deviation_pct=deviation_pct,
            severity=severity,
            org_id=org_id,
            id=id,
            detected_at=detected_at,
            context=context,
            acknowledged=acknowledged,
            acknowledged_at=acknowledged_at,
        )

        anomaly.additional_properties = d
        return anomaly

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
