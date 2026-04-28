from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UtilizationUpdate")


@_attrs_define
class UtilizationUpdate:
    """
    Attributes:
        utilization_pct (float):
        risk_coverage (list[str] | None | Unset):
    """

    utilization_pct: float
    risk_coverage: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        utilization_pct = self.utilization_pct

        risk_coverage: list[str] | None | Unset
        if isinstance(self.risk_coverage, Unset):
            risk_coverage = UNSET
        elif isinstance(self.risk_coverage, list):
            risk_coverage = self.risk_coverage

        else:
            risk_coverage = self.risk_coverage

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "utilization_pct": utilization_pct,
            }
        )
        if risk_coverage is not UNSET:
            field_dict["risk_coverage"] = risk_coverage

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        utilization_pct = d.pop("utilization_pct")

        def _parse_risk_coverage(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                risk_coverage_type_0 = cast(list[str], data)

                return risk_coverage_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        risk_coverage = _parse_risk_coverage(d.pop("risk_coverage", UNSET))

        utilization_update = cls(
            utilization_pct=utilization_pct,
            risk_coverage=risk_coverage,
        )

        utilization_update.additional_properties = d
        return utilization_update

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
