from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.evaluate_dsl_in_input_doc import EvaluateDSLInInputDoc


T = TypeVar("T", bound="EvaluateDSLIn")


@_attrs_define
class EvaluateDSLIn:
    """
    Attributes:
        input_doc (EvaluateDSLInInputDoc | Unset): Input document to evaluate against the rule's `when` block.
    """

    input_doc: EvaluateDSLInInputDoc | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        input_doc: dict[str, Any] | Unset = UNSET
        if not isinstance(self.input_doc, Unset):
            input_doc = self.input_doc.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if input_doc is not UNSET:
            field_dict["input_doc"] = input_doc

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_dsl_in_input_doc import EvaluateDSLInInputDoc

        d = dict(src_dict)
        _input_doc = d.pop("input_doc", UNSET)
        input_doc: EvaluateDSLInInputDoc | Unset
        if isinstance(_input_doc, Unset):
            input_doc = UNSET
        else:
            input_doc = EvaluateDSLInInputDoc.from_dict(_input_doc)

        evaluate_dsl_in = cls(
            input_doc=input_doc,
        )

        evaluate_dsl_in.additional_properties = d
        return evaluate_dsl_in

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
