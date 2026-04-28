from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePenTestResultModel")


@_attrs_define
class CreatePenTestResultModel:
    """Model for creating pen test result.

    Attributes:
        request_id (str):
        finding_id (str):
        exploitability (str):
        exploit_successful (bool):
        evidence (str):
        steps_taken (list[str] | Unset):
        artifacts (list[str] | Unset):
        confidence_score (float | Unset):  Default: 0.0.
        execution_time_seconds (float | Unset):  Default: 0.0.
    """

    request_id: str
    finding_id: str
    exploitability: str
    exploit_successful: bool
    evidence: str
    steps_taken: list[str] | Unset = UNSET
    artifacts: list[str] | Unset = UNSET
    confidence_score: float | Unset = 0.0
    execution_time_seconds: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        request_id = self.request_id

        finding_id = self.finding_id

        exploitability = self.exploitability

        exploit_successful = self.exploit_successful

        evidence = self.evidence

        steps_taken: list[str] | Unset = UNSET
        if not isinstance(self.steps_taken, Unset):
            steps_taken = self.steps_taken

        artifacts: list[str] | Unset = UNSET
        if not isinstance(self.artifacts, Unset):
            artifacts = self.artifacts

        confidence_score = self.confidence_score

        execution_time_seconds = self.execution_time_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "request_id": request_id,
                "finding_id": finding_id,
                "exploitability": exploitability,
                "exploit_successful": exploit_successful,
                "evidence": evidence,
            }
        )
        if steps_taken is not UNSET:
            field_dict["steps_taken"] = steps_taken
        if artifacts is not UNSET:
            field_dict["artifacts"] = artifacts
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if execution_time_seconds is not UNSET:
            field_dict["execution_time_seconds"] = execution_time_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        request_id = d.pop("request_id")

        finding_id = d.pop("finding_id")

        exploitability = d.pop("exploitability")

        exploit_successful = d.pop("exploit_successful")

        evidence = d.pop("evidence")

        steps_taken = cast(list[str], d.pop("steps_taken", UNSET))

        artifacts = cast(list[str], d.pop("artifacts", UNSET))

        confidence_score = d.pop("confidence_score", UNSET)

        execution_time_seconds = d.pop("execution_time_seconds", UNSET)

        create_pen_test_result_model = cls(
            request_id=request_id,
            finding_id=finding_id,
            exploitability=exploitability,
            exploit_successful=exploit_successful,
            evidence=evidence,
            steps_taken=steps_taken,
            artifacts=artifacts,
            confidence_score=confidence_score,
            execution_time_seconds=execution_time_seconds,
        )

        create_pen_test_result_model.additional_properties = d
        return create_pen_test_result_model

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
