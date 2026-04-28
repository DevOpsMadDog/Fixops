from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuestionnaireCreate")


@_attrs_define
class QuestionnaireCreate:
    """
    Attributes:
        questionnaire_name (str):
        questionnaire_type (str | Unset):  Default: 'vendor'.
        framework (str | Unset):  Default: 'custom'.
    """

    questionnaire_name: str
    questionnaire_type: str | Unset = "vendor"
    framework: str | Unset = "custom"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        questionnaire_name = self.questionnaire_name

        questionnaire_type = self.questionnaire_type

        framework = self.framework

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "questionnaire_name": questionnaire_name,
            }
        )
        if questionnaire_type is not UNSET:
            field_dict["questionnaire_type"] = questionnaire_type
        if framework is not UNSET:
            field_dict["framework"] = framework

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        questionnaire_name = d.pop("questionnaire_name")

        questionnaire_type = d.pop("questionnaire_type", UNSET)

        framework = d.pop("framework", UNSET)

        questionnaire_create = cls(
            questionnaire_name=questionnaire_name,
            questionnaire_type=questionnaire_type,
            framework=framework,
        )

        questionnaire_create.additional_properties = d
        return questionnaire_create

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
