from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="NDARequest")


@_attrs_define
class NDARequest:
    """
    Attributes:
        prospect_name (str):
        prospect_email (str):
        prospect_company (str):
    """

    prospect_name: str
    prospect_email: str
    prospect_company: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        prospect_name = self.prospect_name

        prospect_email = self.prospect_email

        prospect_company = self.prospect_company

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "prospect_name": prospect_name,
                "prospect_email": prospect_email,
                "prospect_company": prospect_company,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        prospect_name = d.pop("prospect_name")

        prospect_email = d.pop("prospect_email")

        prospect_company = d.pop("prospect_company")

        nda_request = cls(
            prospect_name=prospect_name,
            prospect_email=prospect_email,
            prospect_company=prospect_company,
        )

        nda_request.additional_properties = d
        return nda_request

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
