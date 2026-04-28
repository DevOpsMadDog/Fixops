from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.questionnaire_response import QuestionnaireResponse


T = TypeVar("T", bound="QuestionnaireSubmitRequest")


@_attrs_define
class QuestionnaireSubmitRequest:
    """Request body for submitting questionnaire responses.

    Attributes:
        responses (list[QuestionnaireResponse]):
        assessed_by (str | Unset): User or system submitting the responses Default: 'api'.
    """

    responses: list[QuestionnaireResponse]
    assessed_by: str | Unset = "api"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        responses = []
        for responses_item_data in self.responses:
            responses_item = responses_item_data.to_dict()
            responses.append(responses_item)

        assessed_by = self.assessed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "responses": responses,
            }
        )
        if assessed_by is not UNSET:
            field_dict["assessed_by"] = assessed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.questionnaire_response import QuestionnaireResponse

        d = dict(src_dict)
        responses = []
        _responses = d.pop("responses")
        for responses_item_data in _responses:
            responses_item = QuestionnaireResponse.from_dict(responses_item_data)

            responses.append(responses_item)

        assessed_by = d.pop("assessed_by", UNSET)

        questionnaire_submit_request = cls(
            responses=responses,
            assessed_by=assessed_by,
        )

        questionnaire_submit_request.additional_properties = d
        return questionnaire_submit_request

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
