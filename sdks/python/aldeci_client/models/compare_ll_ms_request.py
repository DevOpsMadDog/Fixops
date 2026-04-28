from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.compare_ll_ms_request_business_context import CompareLLMsRequestBusinessContext
    from ..models.compare_ll_ms_request_security_findings_item import CompareLLMsRequestSecurityFindingsItem


T = TypeVar("T", bound="CompareLLMsRequest")


@_attrs_define
class CompareLLMsRequest:
    """
    Attributes:
        service_name (str):
        security_findings (list[CompareLLMsRequestSecurityFindingsItem]):
        business_context (CompareLLMsRequestBusinessContext | Unset):
    """

    service_name: str
    security_findings: list[CompareLLMsRequestSecurityFindingsItem]
    business_context: CompareLLMsRequestBusinessContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        service_name = self.service_name

        security_findings = []
        for security_findings_item_data in self.security_findings:
            security_findings_item = security_findings_item_data.to_dict()
            security_findings.append(security_findings_item)

        business_context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.business_context, Unset):
            business_context = self.business_context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "service_name": service_name,
                "security_findings": security_findings,
            }
        )
        if business_context is not UNSET:
            field_dict["business_context"] = business_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compare_ll_ms_request_business_context import CompareLLMsRequestBusinessContext
        from ..models.compare_ll_ms_request_security_findings_item import CompareLLMsRequestSecurityFindingsItem

        d = dict(src_dict)
        service_name = d.pop("service_name")

        security_findings = []
        _security_findings = d.pop("security_findings")
        for security_findings_item_data in _security_findings:
            security_findings_item = CompareLLMsRequestSecurityFindingsItem.from_dict(security_findings_item_data)

            security_findings.append(security_findings_item)

        _business_context = d.pop("business_context", UNSET)
        business_context: CompareLLMsRequestBusinessContext | Unset
        if isinstance(_business_context, Unset):
            business_context = UNSET
        else:
            business_context = CompareLLMsRequestBusinessContext.from_dict(_business_context)

        compare_ll_ms_request = cls(
            service_name=service_name,
            security_findings=security_findings,
            business_context=business_context,
        )

        compare_ll_ms_request.additional_properties = d
        return compare_ll_ms_request

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
