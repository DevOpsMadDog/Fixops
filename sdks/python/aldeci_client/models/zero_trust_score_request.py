from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ZeroTrustScoreRequest")


@_attrs_define
class ZeroTrustScoreRequest:
    """
    Attributes:
        segment (str): Network segment name to score
        org_id (str | Unset):  Default: 'default'.
        device_posture_score (float | Unset): Device posture ratio 0–1 Default: 1.0.
        identity_verified (bool | Unset): All users authenticated via IdP Default: True.
        mfa_enabled (bool | Unset): MFA enforced for all users Default: True.
        network_microsegmented (bool | Unset): Micro-segmentation implemented Default: True.
        app_least_privilege (bool | Unset): App-level least privilege enforced Default: True.
        data_classified (bool | Unset): Data classification implemented Default: True.
    """

    segment: str
    org_id: str | Unset = "default"
    device_posture_score: float | Unset = 1.0
    identity_verified: bool | Unset = True
    mfa_enabled: bool | Unset = True
    network_microsegmented: bool | Unset = True
    app_least_privilege: bool | Unset = True
    data_classified: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        segment = self.segment

        org_id = self.org_id

        device_posture_score = self.device_posture_score

        identity_verified = self.identity_verified

        mfa_enabled = self.mfa_enabled

        network_microsegmented = self.network_microsegmented

        app_least_privilege = self.app_least_privilege

        data_classified = self.data_classified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "segment": segment,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if device_posture_score is not UNSET:
            field_dict["device_posture_score"] = device_posture_score
        if identity_verified is not UNSET:
            field_dict["identity_verified"] = identity_verified
        if mfa_enabled is not UNSET:
            field_dict["mfa_enabled"] = mfa_enabled
        if network_microsegmented is not UNSET:
            field_dict["network_microsegmented"] = network_microsegmented
        if app_least_privilege is not UNSET:
            field_dict["app_least_privilege"] = app_least_privilege
        if data_classified is not UNSET:
            field_dict["data_classified"] = data_classified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        segment = d.pop("segment")

        org_id = d.pop("org_id", UNSET)

        device_posture_score = d.pop("device_posture_score", UNSET)

        identity_verified = d.pop("identity_verified", UNSET)

        mfa_enabled = d.pop("mfa_enabled", UNSET)

        network_microsegmented = d.pop("network_microsegmented", UNSET)

        app_least_privilege = d.pop("app_least_privilege", UNSET)

        data_classified = d.pop("data_classified", UNSET)

        zero_trust_score_request = cls(
            segment=segment,
            org_id=org_id,
            device_posture_score=device_posture_score,
            identity_verified=identity_verified,
            mfa_enabled=mfa_enabled,
            network_microsegmented=network_microsegmented,
            app_least_privilege=app_least_privilege,
            data_classified=data_classified,
        )

        zero_trust_score_request.additional_properties = d
        return zero_trust_score_request

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
