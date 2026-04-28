from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.industry_vertical import IndustryVertical
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.generate_benchmark_request_org_metrics_type_0 import GenerateBenchmarkRequestOrgMetricsType0


T = TypeVar("T", bound="GenerateBenchmarkRequest")


@_attrs_define
class GenerateBenchmarkRequest:
    """
    Attributes:
        vertical (IndustryVertical): Industry verticals for benchmark comparison.
        org_id (str | Unset): Organisation identifier Default: 'default'.
        org_metrics (GenerateBenchmarkRequestOrgMetricsType0 | None | Unset): Metric name -> measured value (optional;
            previously stored values used if omitted)
    """

    vertical: IndustryVertical
    org_id: str | Unset = "default"
    org_metrics: GenerateBenchmarkRequestOrgMetricsType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.generate_benchmark_request_org_metrics_type_0 import GenerateBenchmarkRequestOrgMetricsType0

        vertical = self.vertical.value

        org_id = self.org_id

        org_metrics: dict[str, Any] | None | Unset
        if isinstance(self.org_metrics, Unset):
            org_metrics = UNSET
        elif isinstance(self.org_metrics, GenerateBenchmarkRequestOrgMetricsType0):
            org_metrics = self.org_metrics.to_dict()
        else:
            org_metrics = self.org_metrics

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vertical": vertical,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if org_metrics is not UNSET:
            field_dict["org_metrics"] = org_metrics

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.generate_benchmark_request_org_metrics_type_0 import GenerateBenchmarkRequestOrgMetricsType0

        d = dict(src_dict)
        vertical = IndustryVertical(d.pop("vertical"))

        org_id = d.pop("org_id", UNSET)

        def _parse_org_metrics(data: object) -> GenerateBenchmarkRequestOrgMetricsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                org_metrics_type_0 = GenerateBenchmarkRequestOrgMetricsType0.from_dict(data)

                return org_metrics_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GenerateBenchmarkRequestOrgMetricsType0 | None | Unset, data)

        org_metrics = _parse_org_metrics(d.pop("org_metrics", UNSET))

        generate_benchmark_request = cls(
            vertical=vertical,
            org_id=org_id,
            org_metrics=org_metrics,
        )

        generate_benchmark_request.additional_properties = d
        return generate_benchmark_request

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
