from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.generate_report_request_findings_context_type_0 import GenerateReportRequestFindingsContextType0


T = TypeVar("T", bound="GenerateReportRequest")


@_attrs_define
class GenerateReportRequest:
    """Request body for generating a compliance report.

    Attributes:
        framework (str): One of: SOC2, PCI, HIPAA, ISO27001, NIST, GDPR, CIS
        title (None | str | Unset):
        findings_context (GenerateReportRequestFindingsContextType0 | None | Unset):
    """

    framework: str
    title: None | str | Unset = UNSET
    findings_context: GenerateReportRequestFindingsContextType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.generate_report_request_findings_context_type_0 import GenerateReportRequestFindingsContextType0

        framework = self.framework

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        findings_context: dict[str, Any] | None | Unset
        if isinstance(self.findings_context, Unset):
            findings_context = UNSET
        elif isinstance(self.findings_context, GenerateReportRequestFindingsContextType0):
            findings_context = self.findings_context.to_dict()
        else:
            findings_context = self.findings_context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
            }
        )
        if title is not UNSET:
            field_dict["title"] = title
        if findings_context is not UNSET:
            field_dict["findings_context"] = findings_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.generate_report_request_findings_context_type_0 import GenerateReportRequestFindingsContextType0

        d = dict(src_dict)
        framework = d.pop("framework")

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        def _parse_findings_context(data: object) -> GenerateReportRequestFindingsContextType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                findings_context_type_0 = GenerateReportRequestFindingsContextType0.from_dict(data)

                return findings_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GenerateReportRequestFindingsContextType0 | None | Unset, data)

        findings_context = _parse_findings_context(d.pop("findings_context", UNSET))

        generate_report_request = cls(
            framework=framework,
            title=title,
            findings_context=findings_context,
        )

        generate_report_request.additional_properties = d
        return generate_report_request

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
