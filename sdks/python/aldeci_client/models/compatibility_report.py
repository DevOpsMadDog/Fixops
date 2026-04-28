from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.validation_result import ValidationResult


T = TypeVar("T", bound="CompatibilityReport")


@_attrs_define
class CompatibilityReport:
    """Detailed compatibility report for customer validation.

    Attributes:
        timestamp (str):
        validation_results (list[ValidationResult]):
        overall_compatible (bool):
        fixops_version (str | Unset):  Default: '1.0.0'.
        recommendations (list[str] | Unset):
    """

    timestamp: str
    validation_results: list[ValidationResult]
    overall_compatible: bool
    fixops_version: str | Unset = "1.0.0"
    recommendations: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        timestamp = self.timestamp

        validation_results = []
        for validation_results_item_data in self.validation_results:
            validation_results_item = validation_results_item_data.to_dict()
            validation_results.append(validation_results_item)

        overall_compatible = self.overall_compatible

        fixops_version = self.fixops_version

        recommendations: list[str] | Unset = UNSET
        if not isinstance(self.recommendations, Unset):
            recommendations = self.recommendations

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "timestamp": timestamp,
                "validation_results": validation_results,
                "overall_compatible": overall_compatible,
            }
        )
        if fixops_version is not UNSET:
            field_dict["fixops_version"] = fixops_version
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.validation_result import ValidationResult

        d = dict(src_dict)
        timestamp = d.pop("timestamp")

        validation_results = []
        _validation_results = d.pop("validation_results")
        for validation_results_item_data in _validation_results:
            validation_results_item = ValidationResult.from_dict(validation_results_item_data)

            validation_results.append(validation_results_item)

        overall_compatible = d.pop("overall_compatible")

        fixops_version = d.pop("fixops_version", UNSET)

        recommendations = cast(list[str], d.pop("recommendations", UNSET))

        compatibility_report = cls(
            timestamp=timestamp,
            validation_results=validation_results,
            overall_compatible=overall_compatible,
            fixops_version=fixops_version,
            recommendations=recommendations,
        )

        compatibility_report.additional_properties = d
        return compatibility_report

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
