from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cve_risk_request import CVERiskRequest


T = TypeVar("T", bound="PortfolioRiskRequest")


@_attrs_define
class PortfolioRiskRequest:
    """Request for portfolio-level risk quantification.

    Attributes:
        vulnerabilities (list[CVERiskRequest]): List of vulnerabilities
        correlation (float | Unset): Cross-vulnerability correlation Default: 0.3.
    """

    vulnerabilities: list[CVERiskRequest]
    correlation: float | Unset = 0.3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vulnerabilities = []
        for vulnerabilities_item_data in self.vulnerabilities:
            vulnerabilities_item = vulnerabilities_item_data.to_dict()
            vulnerabilities.append(vulnerabilities_item)

        correlation = self.correlation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vulnerabilities": vulnerabilities,
            }
        )
        if correlation is not UNSET:
            field_dict["correlation"] = correlation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cve_risk_request import CVERiskRequest

        d = dict(src_dict)
        vulnerabilities = []
        _vulnerabilities = d.pop("vulnerabilities")
        for vulnerabilities_item_data in _vulnerabilities:
            vulnerabilities_item = CVERiskRequest.from_dict(vulnerabilities_item_data)

            vulnerabilities.append(vulnerabilities_item)

        correlation = d.pop("correlation", UNSET)

        portfolio_risk_request = cls(
            vulnerabilities=vulnerabilities,
            correlation=correlation,
        )

        portfolio_risk_request.additional_properties = d
        return portfolio_risk_request

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
