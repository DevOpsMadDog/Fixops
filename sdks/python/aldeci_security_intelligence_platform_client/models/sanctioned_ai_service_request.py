from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SanctionedAIServiceRequest")


@_attrs_define
class SanctionedAIServiceRequest:
    """
    Attributes:
        service_name (str):
        provider (str | Unset):  Default: ''.
        data_classification (str | Unset):  Default: 'internal'.
        approved_by (str | Unset):  Default: ''.
    """

    service_name: str
    provider: str | Unset = ""
    data_classification: str | Unset = "internal"
    approved_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        service_name = self.service_name

        provider = self.provider

        data_classification = self.data_classification

        approved_by = self.approved_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "service_name": service_name,
            }
        )
        if provider is not UNSET:
            field_dict["provider"] = provider
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        service_name = d.pop("service_name")

        provider = d.pop("provider", UNSET)

        data_classification = d.pop("data_classification", UNSET)

        approved_by = d.pop("approved_by", UNSET)

        sanctioned_ai_service_request = cls(
            service_name=service_name,
            provider=provider,
            data_classification=data_classification,
            approved_by=approved_by,
        )

        sanctioned_ai_service_request.additional_properties = d
        return sanctioned_ai_service_request

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
