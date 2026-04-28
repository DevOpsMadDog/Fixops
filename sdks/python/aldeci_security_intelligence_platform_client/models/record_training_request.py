from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordTrainingRequest")


@_attrs_define
class RecordTrainingRequest:
    """
    Attributes:
        training_name (str):
        training_type (str | Unset):  Default: 'security_basics'.
        completed_at (None | str | Unset):
        score (float | Unset):  Default: 0.0.
        passed (int | None | Unset):
        expires_at (None | str | Unset):
    """

    training_name: str
    training_type: str | Unset = "security_basics"
    completed_at: None | str | Unset = UNSET
    score: float | Unset = 0.0
    passed: int | None | Unset = UNSET
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        training_name = self.training_name

        training_type = self.training_type

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        score = self.score

        passed: int | None | Unset
        if isinstance(self.passed, Unset):
            passed = UNSET
        else:
            passed = self.passed

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "training_name": training_name,
            }
        )
        if training_type is not UNSET:
            field_dict["training_type"] = training_type
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if score is not UNSET:
            field_dict["score"] = score
        if passed is not UNSET:
            field_dict["passed"] = passed
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        training_name = d.pop("training_name")

        training_type = d.pop("training_type", UNSET)

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        score = d.pop("score", UNSET)

        def _parse_passed(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        passed = _parse_passed(d.pop("passed", UNSET))

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        record_training_request = cls(
            training_name=training_name,
            training_type=training_type,
            completed_at=completed_at,
            score=score,
            passed=passed,
            expires_at=expires_at,
        )

        record_training_request.additional_properties = d
        return record_training_request

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
