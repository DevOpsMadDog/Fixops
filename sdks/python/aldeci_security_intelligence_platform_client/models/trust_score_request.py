from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TrustScoreRequest")


@_attrs_define
class TrustScoreRequest:
    """
    Attributes:
        user_id (str | Unset):  Default: ''.
        device_compliant (bool | Unset):  Default: False.
        mfa_verified (bool | Unset):  Default: False.
        user_risk_score (float | Unset):  Default: 0.0.
    """

    user_id: str | Unset = ""
    device_compliant: bool | Unset = False
    mfa_verified: bool | Unset = False
    user_risk_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        device_compliant = self.device_compliant

        mfa_verified = self.mfa_verified

        user_risk_score = self.user_risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if user_id is not UNSET:
            field_dict["user_id"] = user_id
        if device_compliant is not UNSET:
            field_dict["device_compliant"] = device_compliant
        if mfa_verified is not UNSET:
            field_dict["mfa_verified"] = mfa_verified
        if user_risk_score is not UNSET:
            field_dict["user_risk_score"] = user_risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id", UNSET)

        device_compliant = d.pop("device_compliant", UNSET)

        mfa_verified = d.pop("mfa_verified", UNSET)

        user_risk_score = d.pop("user_risk_score", UNSET)

        trust_score_request = cls(
            user_id=user_id,
            device_compliant=device_compliant,
            mfa_verified=mfa_verified,
            user_risk_score=user_risk_score,
        )

        trust_score_request.additional_properties = d
        return trust_score_request

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
