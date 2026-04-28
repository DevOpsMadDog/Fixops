from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.risk_calculate_request_factors_item import RiskCalculateRequestFactorsItem


T = TypeVar("T", bound="RiskCalculateRequest")


@_attrs_define
class RiskCalculateRequest:
    """
    Attributes:
        factors (list[RiskCalculateRequestFactorsItem] | Unset): List of score dicts with optional keys: vuln_score,
            threat_score, exposure_score, compliance_score (0-100)
    """

    factors: list[RiskCalculateRequestFactorsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        factors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.factors, Unset):
            factors = []
            for factors_item_data in self.factors:
                factors_item = factors_item_data.to_dict()
                factors.append(factors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if factors is not UNSET:
            field_dict["factors"] = factors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.risk_calculate_request_factors_item import RiskCalculateRequestFactorsItem

        d = dict(src_dict)
        _factors = d.pop("factors", UNSET)
        factors: list[RiskCalculateRequestFactorsItem] | Unset = UNSET
        if _factors is not UNSET:
            factors = []
            for factors_item_data in _factors:
                factors_item = RiskCalculateRequestFactorsItem.from_dict(factors_item_data)

                factors.append(factors_item)

        risk_calculate_request = cls(
            factors=factors,
        )

        risk_calculate_request.additional_properties = d
        return risk_calculate_request

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
