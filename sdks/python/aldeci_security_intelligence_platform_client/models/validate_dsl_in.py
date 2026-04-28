from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ValidateDSLIn")


@_attrs_define
class ValidateDSLIn:
    """
    Attributes:
        dsl_text (str): Raw YAML or JSON rule text
        dsl_format (str | Unset): 'yaml' or 'json' Default: 'yaml'.
    """

    dsl_text: str
    dsl_format: str | Unset = "yaml"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dsl_text = self.dsl_text

        dsl_format = self.dsl_format

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dsl_text": dsl_text,
            }
        )
        if dsl_format is not UNSET:
            field_dict["dsl_format"] = dsl_format

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dsl_text = d.pop("dsl_text")

        dsl_format = d.pop("dsl_format", UNSET)

        validate_dsl_in = cls(
            dsl_text=dsl_text,
            dsl_format=dsl_format,
        )

        validate_dsl_in.additional_properties = d
        return validate_dsl_in

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
