from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.azure_analyze_request_role_definition import AzureAnalyzeRequestRoleDefinition


T = TypeVar("T", bound="AzureAnalyzeRequest")


@_attrs_define
class AzureAnalyzeRequest:
    """
    Attributes:
        role_definition (AzureAnalyzeRequestRoleDefinition): Azure role definition or assignment JSON
        principal (str): Azure object ID, UPN, or display name
    """

    role_definition: AzureAnalyzeRequestRoleDefinition
    principal: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        role_definition = self.role_definition.to_dict()

        principal = self.principal

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "role_definition": role_definition,
                "principal": principal,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.azure_analyze_request_role_definition import AzureAnalyzeRequestRoleDefinition

        d = dict(src_dict)
        role_definition = AzureAnalyzeRequestRoleDefinition.from_dict(d.pop("role_definition"))

        principal = d.pop("principal")

        azure_analyze_request = cls(
            role_definition=role_definition,
            principal=principal,
        )

        azure_analyze_request.additional_properties = d
        return azure_analyze_request

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
