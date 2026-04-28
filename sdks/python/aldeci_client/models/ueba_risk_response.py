from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.user_risk_score import UserRiskScore


T = TypeVar("T", bound="UEBARiskResponse")


@_attrs_define
class UEBARiskResponse:
    """
    Attributes:
        user_risk (UserRiskScore): Composite UEBA risk score for a user.
    """

    user_risk: UserRiskScore
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_risk = self.user_risk.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_risk": user_risk,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.user_risk_score import UserRiskScore

        d = dict(src_dict)
        user_risk = UserRiskScore.from_dict(d.pop("user_risk"))

        ueba_risk_response = cls(
            user_risk=user_risk,
        )

        ueba_risk_response.additional_properties = d
        return ueba_risk_response

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
