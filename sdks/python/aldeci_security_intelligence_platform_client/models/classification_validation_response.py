from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ClassificationValidationResponse")


@_attrs_define
class ClassificationValidationResponse:
    """
    Attributes:
        app_id (str):
        valid (bool):
        data_classification (str):
        policy_classification_level (str):
        issues (list[str]):
    """

    app_id: str
    valid: bool
    data_classification: str
    policy_classification_level: str
    issues: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        valid = self.valid

        data_classification = self.data_classification

        policy_classification_level = self.policy_classification_level

        issues = self.issues

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
                "valid": valid,
                "data_classification": data_classification,
                "policy_classification_level": policy_classification_level,
                "issues": issues,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_id = d.pop("app_id")

        valid = d.pop("valid")

        data_classification = d.pop("data_classification")

        policy_classification_level = d.pop("policy_classification_level")

        issues = cast(list[str], d.pop("issues"))

        classification_validation_response = cls(
            app_id=app_id,
            valid=valid,
            data_classification=data_classification,
            policy_classification_level=policy_classification_level,
            issues=issues,
        )

        classification_validation_response.additional_properties = d
        return classification_validation_response

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
