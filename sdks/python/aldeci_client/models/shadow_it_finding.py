from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.asset_category import AssetCategory
from ..models.exposure_zone import ExposureZone
from ..models.risk_tier import RiskTier
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.shadow_it_finding_details import ShadowITFindingDetails


T = TypeVar("T", bound="ShadowITFinding")


@_attrs_define
class ShadowITFinding:
    """Unmanaged / rogue asset detected via shadow IT scan.

    Attributes:
        asset_name (str):
        asset_category (AssetCategory):
        exposure_zone (ExposureZone):
        reason (str):
        id (str | Unset):
        org_id (str | Unset):  Default: 'default'.
        risk_tier (RiskTier | Unset):
        detected_at (str | Unset):
        details (ShadowITFindingDetails | Unset):
    """

    asset_name: str
    asset_category: AssetCategory
    exposure_zone: ExposureZone
    reason: str
    id: str | Unset = UNSET
    org_id: str | Unset = "default"
    risk_tier: RiskTier | Unset = UNSET
    detected_at: str | Unset = UNSET
    details: ShadowITFindingDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_name = self.asset_name

        asset_category = self.asset_category.value

        exposure_zone = self.exposure_zone.value

        reason = self.reason

        id = self.id

        org_id = self.org_id

        risk_tier: str | Unset = UNSET
        if not isinstance(self.risk_tier, Unset):
            risk_tier = self.risk_tier.value

        detected_at = self.detected_at

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "asset_name": asset_name,
                "asset_category": asset_category,
                "exposure_zone": exposure_zone,
                "reason": reason,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if risk_tier is not UNSET:
            field_dict["risk_tier"] = risk_tier
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.shadow_it_finding_details import ShadowITFindingDetails

        d = dict(src_dict)
        asset_name = d.pop("asset_name")

        asset_category = AssetCategory(d.pop("asset_category"))

        exposure_zone = ExposureZone(d.pop("exposure_zone"))

        reason = d.pop("reason")

        id = d.pop("id", UNSET)

        org_id = d.pop("org_id", UNSET)

        _risk_tier = d.pop("risk_tier", UNSET)
        risk_tier: RiskTier | Unset
        if isinstance(_risk_tier, Unset):
            risk_tier = UNSET
        else:
            risk_tier = RiskTier(_risk_tier)

        detected_at = d.pop("detected_at", UNSET)

        _details = d.pop("details", UNSET)
        details: ShadowITFindingDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = ShadowITFindingDetails.from_dict(_details)

        shadow_it_finding = cls(
            asset_name=asset_name,
            asset_category=asset_category,
            exposure_zone=exposure_zone,
            reason=reason,
            id=id,
            org_id=org_id,
            risk_tier=risk_tier,
            detected_at=detected_at,
            details=details,
        )

        shadow_it_finding.additional_properties = d
        return shadow_it_finding

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
