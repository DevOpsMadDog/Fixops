from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordStepRequest")


@_attrs_define
class RecordStepRequest:
    """
    Attributes:
        outcome (str): Step outcome: executed, detected, blocked, missed
        detected (bool | Unset): Was the step detected by ALDECI? Default: False.
        detection_engine (str | Unset): Which ALDECI engine detected it: siem, edr, ndr, soar, threat_intel, anomaly,
            manual, none Default: 'none'.
        alert_fired (bool | Unset): Did an alert fire in the platform? Default: False.
        time_to_detect_seconds (float | None | Unset): Seconds from attack execution to detection
        detection_notes (str | Unset): Free-text detection notes Default: ''.
    """

    outcome: str
    detected: bool | Unset = False
    detection_engine: str | Unset = "none"
    alert_fired: bool | Unset = False
    time_to_detect_seconds: float | None | Unset = UNSET
    detection_notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        outcome = self.outcome

        detected = self.detected

        detection_engine = self.detection_engine

        alert_fired = self.alert_fired

        time_to_detect_seconds: float | None | Unset
        if isinstance(self.time_to_detect_seconds, Unset):
            time_to_detect_seconds = UNSET
        else:
            time_to_detect_seconds = self.time_to_detect_seconds

        detection_notes = self.detection_notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "outcome": outcome,
            }
        )
        if detected is not UNSET:
            field_dict["detected"] = detected
        if detection_engine is not UNSET:
            field_dict["detection_engine"] = detection_engine
        if alert_fired is not UNSET:
            field_dict["alert_fired"] = alert_fired
        if time_to_detect_seconds is not UNSET:
            field_dict["time_to_detect_seconds"] = time_to_detect_seconds
        if detection_notes is not UNSET:
            field_dict["detection_notes"] = detection_notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        outcome = d.pop("outcome")

        detected = d.pop("detected", UNSET)

        detection_engine = d.pop("detection_engine", UNSET)

        alert_fired = d.pop("alert_fired", UNSET)

        def _parse_time_to_detect_seconds(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        time_to_detect_seconds = _parse_time_to_detect_seconds(d.pop("time_to_detect_seconds", UNSET))

        detection_notes = d.pop("detection_notes", UNSET)

        record_step_request = cls(
            outcome=outcome,
            detected=detected,
            detection_engine=detection_engine,
            alert_fired=alert_fired,
            time_to_detect_seconds=time_to_detect_seconds,
            detection_notes=detection_notes,
        )

        record_step_request.additional_properties = d
        return record_step_request

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
