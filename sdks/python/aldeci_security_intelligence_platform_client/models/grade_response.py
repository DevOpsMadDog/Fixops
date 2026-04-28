from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GradeResponse")


@_attrs_define
class GradeResponse:
    """Drill score response.

    Attributes:
        drill_id (str):
        detection_speed (float):
        triage_accuracy (float):
        remediation_speed (float):
        communication (float):
        overall (float):
        grade (str):
        escalated_correctly (bool):
        team_notified (bool):
        feedback (list[str]):
        detection_minutes_actual (int | None | Unset):
        detection_minutes_target (int | None | Unset):
        triage_classification_actual (None | str | Unset):
        triage_classification_expected (None | str | Unset):
        remediation_minutes_actual (int | None | Unset):
    """

    drill_id: str
    detection_speed: float
    triage_accuracy: float
    remediation_speed: float
    communication: float
    overall: float
    grade: str
    escalated_correctly: bool
    team_notified: bool
    feedback: list[str]
    detection_minutes_actual: int | None | Unset = UNSET
    detection_minutes_target: int | None | Unset = UNSET
    triage_classification_actual: None | str | Unset = UNSET
    triage_classification_expected: None | str | Unset = UNSET
    remediation_minutes_actual: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        drill_id = self.drill_id

        detection_speed = self.detection_speed

        triage_accuracy = self.triage_accuracy

        remediation_speed = self.remediation_speed

        communication = self.communication

        overall = self.overall

        grade = self.grade

        escalated_correctly = self.escalated_correctly

        team_notified = self.team_notified

        feedback = self.feedback

        detection_minutes_actual: int | None | Unset
        if isinstance(self.detection_minutes_actual, Unset):
            detection_minutes_actual = UNSET
        else:
            detection_minutes_actual = self.detection_minutes_actual

        detection_minutes_target: int | None | Unset
        if isinstance(self.detection_minutes_target, Unset):
            detection_minutes_target = UNSET
        else:
            detection_minutes_target = self.detection_minutes_target

        triage_classification_actual: None | str | Unset
        if isinstance(self.triage_classification_actual, Unset):
            triage_classification_actual = UNSET
        else:
            triage_classification_actual = self.triage_classification_actual

        triage_classification_expected: None | str | Unset
        if isinstance(self.triage_classification_expected, Unset):
            triage_classification_expected = UNSET
        else:
            triage_classification_expected = self.triage_classification_expected

        remediation_minutes_actual: int | None | Unset
        if isinstance(self.remediation_minutes_actual, Unset):
            remediation_minutes_actual = UNSET
        else:
            remediation_minutes_actual = self.remediation_minutes_actual

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "drill_id": drill_id,
                "detection_speed": detection_speed,
                "triage_accuracy": triage_accuracy,
                "remediation_speed": remediation_speed,
                "communication": communication,
                "overall": overall,
                "grade": grade,
                "escalated_correctly": escalated_correctly,
                "team_notified": team_notified,
                "feedback": feedback,
            }
        )
        if detection_minutes_actual is not UNSET:
            field_dict["detection_minutes_actual"] = detection_minutes_actual
        if detection_minutes_target is not UNSET:
            field_dict["detection_minutes_target"] = detection_minutes_target
        if triage_classification_actual is not UNSET:
            field_dict["triage_classification_actual"] = triage_classification_actual
        if triage_classification_expected is not UNSET:
            field_dict["triage_classification_expected"] = triage_classification_expected
        if remediation_minutes_actual is not UNSET:
            field_dict["remediation_minutes_actual"] = remediation_minutes_actual

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        drill_id = d.pop("drill_id")

        detection_speed = d.pop("detection_speed")

        triage_accuracy = d.pop("triage_accuracy")

        remediation_speed = d.pop("remediation_speed")

        communication = d.pop("communication")

        overall = d.pop("overall")

        grade = d.pop("grade")

        escalated_correctly = d.pop("escalated_correctly")

        team_notified = d.pop("team_notified")

        feedback = cast(list[str], d.pop("feedback"))

        def _parse_detection_minutes_actual(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        detection_minutes_actual = _parse_detection_minutes_actual(d.pop("detection_minutes_actual", UNSET))

        def _parse_detection_minutes_target(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        detection_minutes_target = _parse_detection_minutes_target(d.pop("detection_minutes_target", UNSET))

        def _parse_triage_classification_actual(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        triage_classification_actual = _parse_triage_classification_actual(d.pop("triage_classification_actual", UNSET))

        def _parse_triage_classification_expected(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        triage_classification_expected = _parse_triage_classification_expected(
            d.pop("triage_classification_expected", UNSET)
        )

        def _parse_remediation_minutes_actual(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        remediation_minutes_actual = _parse_remediation_minutes_actual(d.pop("remediation_minutes_actual", UNSET))

        grade_response = cls(
            drill_id=drill_id,
            detection_speed=detection_speed,
            triage_accuracy=triage_accuracy,
            remediation_speed=remediation_speed,
            communication=communication,
            overall=overall,
            grade=grade,
            escalated_correctly=escalated_correctly,
            team_notified=team_notified,
            feedback=feedback,
            detection_minutes_actual=detection_minutes_actual,
            detection_minutes_target=detection_minutes_target,
            triage_classification_actual=triage_classification_actual,
            triage_classification_expected=triage_classification_expected,
            remediation_minutes_actual=remediation_minutes_actual,
        )

        grade_response.additional_properties = d
        return grade_response

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
