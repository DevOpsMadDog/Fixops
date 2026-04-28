from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="FourthPartyRiskResponse")


@_attrs_define
class FourthPartyRiskResponse:
    """Fourth-party risk score for a vendor.

    Attributes:
        vendor_id (str):
        fourth_party_risk_score (float):
        risk_label (str):
    """

    vendor_id: str
    fourth_party_risk_score: float
    risk_label: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vendor_id = self.vendor_id

        fourth_party_risk_score = self.fourth_party_risk_score

        risk_label = self.risk_label

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vendor_id": vendor_id,
                "fourth_party_risk_score": fourth_party_risk_score,
                "risk_label": risk_label,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vendor_id = d.pop("vendor_id")

        fourth_party_risk_score = d.pop("fourth_party_risk_score")

        risk_label = d.pop("risk_label")

        fourth_party_risk_response = cls(
            vendor_id=vendor_id,
            fourth_party_risk_score=fourth_party_risk_score,
            risk_label=risk_label,
        )

        fourth_party_risk_response.additional_properties = d
        return fourth_party_risk_response

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
