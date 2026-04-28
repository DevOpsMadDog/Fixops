from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssessmentIn")


@_attrs_define
class AssessmentIn:
    """
    Attributes:
        policy_id (str):
        mfa_score (int | Unset):  Default: 0.
        backup_score (int | Unset):  Default: 0.
        incident_response_score (int | Unset):  Default: 0.
        patch_score (int | Unset):  Default: 0.
        training_score (int | Unset):  Default: 0.
        recommendations (list[str] | Unset):
        assessed_at (None | str | Unset):
    """

    policy_id: str
    mfa_score: int | Unset = 0
    backup_score: int | Unset = 0
    incident_response_score: int | Unset = 0
    patch_score: int | Unset = 0
    training_score: int | Unset = 0
    recommendations: list[str] | Unset = UNSET
    assessed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        mfa_score = self.mfa_score

        backup_score = self.backup_score

        incident_response_score = self.incident_response_score

        patch_score = self.patch_score

        training_score = self.training_score

        recommendations: list[str] | Unset = UNSET
        if not isinstance(self.recommendations, Unset):
            recommendations = self.recommendations

        assessed_at: None | str | Unset
        if isinstance(self.assessed_at, Unset):
            assessed_at = UNSET
        else:
            assessed_at = self.assessed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
            }
        )
        if mfa_score is not UNSET:
            field_dict["mfa_score"] = mfa_score
        if backup_score is not UNSET:
            field_dict["backup_score"] = backup_score
        if incident_response_score is not UNSET:
            field_dict["incident_response_score"] = incident_response_score
        if patch_score is not UNSET:
            field_dict["patch_score"] = patch_score
        if training_score is not UNSET:
            field_dict["training_score"] = training_score
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations
        if assessed_at is not UNSET:
            field_dict["assessed_at"] = assessed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        mfa_score = d.pop("mfa_score", UNSET)

        backup_score = d.pop("backup_score", UNSET)

        incident_response_score = d.pop("incident_response_score", UNSET)

        patch_score = d.pop("patch_score", UNSET)

        training_score = d.pop("training_score", UNSET)

        recommendations = cast(list[str], d.pop("recommendations", UNSET))

        def _parse_assessed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assessed_at = _parse_assessed_at(d.pop("assessed_at", UNSET))

        assessment_in = cls(
            policy_id=policy_id,
            mfa_score=mfa_score,
            backup_score=backup_score,
            incident_response_score=incident_response_score,
            patch_score=patch_score,
            training_score=training_score,
            recommendations=recommendations,
            assessed_at=assessed_at,
        )

        assessment_in.additional_properties = d
        return assessment_in

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
