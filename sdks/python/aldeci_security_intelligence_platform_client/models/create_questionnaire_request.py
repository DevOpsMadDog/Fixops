from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_questionnaire_request_custom_questions_type_0_item import (
        CreateQuestionnaireRequestCustomQuestionsType0Item,
    )


T = TypeVar("T", bound="CreateQuestionnaireRequest")


@_attrs_define
class CreateQuestionnaireRequest:
    """
    Attributes:
        name (str): Questionnaire display name
        vendor_name (str): Target vendor / recipient name
        org_id (str | Unset): Organisation identifier Default: 'default'.
        template_type (None | str | Unset): One of: soc2, vendor_assessment, sig_lite
        custom_questions (list[CreateQuestionnaireRequestCustomQuestionsType0Item] | None | Unset): Custom questions
            list: [{text: str, category: str}]
    """

    name: str
    vendor_name: str
    org_id: str | Unset = "default"
    template_type: None | str | Unset = UNSET
    custom_questions: list[CreateQuestionnaireRequestCustomQuestionsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        vendor_name = self.vendor_name

        org_id = self.org_id

        template_type: None | str | Unset
        if isinstance(self.template_type, Unset):
            template_type = UNSET
        else:
            template_type = self.template_type

        custom_questions: list[dict[str, Any]] | None | Unset
        if isinstance(self.custom_questions, Unset):
            custom_questions = UNSET
        elif isinstance(self.custom_questions, list):
            custom_questions = []
            for custom_questions_type_0_item_data in self.custom_questions:
                custom_questions_type_0_item = custom_questions_type_0_item_data.to_dict()
                custom_questions.append(custom_questions_type_0_item)

        else:
            custom_questions = self.custom_questions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "vendor_name": vendor_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if template_type is not UNSET:
            field_dict["template_type"] = template_type
        if custom_questions is not UNSET:
            field_dict["custom_questions"] = custom_questions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_questionnaire_request_custom_questions_type_0_item import (
            CreateQuestionnaireRequestCustomQuestionsType0Item,
        )

        d = dict(src_dict)
        name = d.pop("name")

        vendor_name = d.pop("vendor_name")

        org_id = d.pop("org_id", UNSET)

        def _parse_template_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        template_type = _parse_template_type(d.pop("template_type", UNSET))

        def _parse_custom_questions(
            data: object,
        ) -> list[CreateQuestionnaireRequestCustomQuestionsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                custom_questions_type_0 = []
                _custom_questions_type_0 = data
                for custom_questions_type_0_item_data in _custom_questions_type_0:
                    custom_questions_type_0_item = CreateQuestionnaireRequestCustomQuestionsType0Item.from_dict(
                        custom_questions_type_0_item_data
                    )

                    custom_questions_type_0.append(custom_questions_type_0_item)

                return custom_questions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[CreateQuestionnaireRequestCustomQuestionsType0Item] | None | Unset, data)

        custom_questions = _parse_custom_questions(d.pop("custom_questions", UNSET))

        create_questionnaire_request = cls(
            name=name,
            vendor_name=vendor_name,
            org_id=org_id,
            template_type=template_type,
            custom_questions=custom_questions,
        )

        create_questionnaire_request.additional_properties = d
        return create_questionnaire_request

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
