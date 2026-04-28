from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.core_coverage_response import CoreCoverageResponse


T = TypeVar("T", bound="CoverageReportResponseCores")


@_attrs_define
class CoverageReportResponseCores:
    """ """

    additional_properties: dict[str, CoreCoverageResponse] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        for prop_name, prop in self.additional_properties.items():
            field_dict[prop_name] = prop.to_dict()

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.core_coverage_response import CoreCoverageResponse

        d = dict(src_dict)
        coverage_report_response_cores = cls()

        additional_properties = {}
        for prop_name, prop_dict in d.items():
            additional_property = CoreCoverageResponse.from_dict(prop_dict)

            additional_properties[prop_name] = additional_property

        coverage_report_response_cores.additional_properties = additional_properties
        return coverage_report_response_cores

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> CoreCoverageResponse:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: CoreCoverageResponse) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
