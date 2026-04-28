from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AssessmentSend")


@_attrs_define
class AssessmentSend:
    """
    Attributes:
        questionnaire_id (str):
        vendor_id (str):
        vendor_name (str):
        due_date (str):
    """

    questionnaire_id: str
    vendor_id: str
    vendor_name: str
    due_date: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        questionnaire_id = self.questionnaire_id

        vendor_id = self.vendor_id

        vendor_name = self.vendor_name

        due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "questionnaire_id": questionnaire_id,
                "vendor_id": vendor_id,
                "vendor_name": vendor_name,
                "due_date": due_date,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        questionnaire_id = d.pop("questionnaire_id")

        vendor_id = d.pop("vendor_id")

        vendor_name = d.pop("vendor_name")

        due_date = d.pop("due_date")

        assessment_send = cls(
            questionnaire_id=questionnaire_id,
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            due_date=due_date,
        )

        assessment_send.additional_properties = d
        return assessment_send

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
