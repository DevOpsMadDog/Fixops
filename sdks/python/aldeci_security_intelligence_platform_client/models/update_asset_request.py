from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.asset_criticality import AssetCriticality
from ..models.criticality_tier import CriticalityTier
from ..models.data_classification import DataClassification
from ..models.environment import Environment
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_asset_request_metadata_type_0 import UpdateAssetRequestMetadataType0


T = TypeVar("T", bound="UpdateAssetRequest")


@_attrs_define
class UpdateAssetRequest:
    """
    Attributes:
        name (None | str | Unset):
        asset_type (None | str | Unset):
        hostname (None | str | Unset):
        ip_address (None | str | Unset):
        cloud_provider (None | str | Unset):
        region (None | str | Unset):
        cloud_resource_id (None | str | Unset):
        owner_email (None | str | Unset):
        owner_name (None | str | Unset):
        team (None | str | Unset):
        business_unit (None | str | Unset):
        cost_center (None | str | Unset):
        criticality (AssetCriticality | None | Unset):
        criticality_tier (CriticalityTier | None | Unset):
        data_classification (DataClassification | None | Unset):
        compliance_scope (list[str] | None | Unset):
        environment (Environment | None | Unset):
        tags (list[str] | None | Unset):
        metadata (None | Unset | UpdateAssetRequestMetadataType0):
        risk_score (float | None | Unset):
        finding_count (int | None | Unset):
    """

    name: None | str | Unset = UNSET
    asset_type: None | str | Unset = UNSET
    hostname: None | str | Unset = UNSET
    ip_address: None | str | Unset = UNSET
    cloud_provider: None | str | Unset = UNSET
    region: None | str | Unset = UNSET
    cloud_resource_id: None | str | Unset = UNSET
    owner_email: None | str | Unset = UNSET
    owner_name: None | str | Unset = UNSET
    team: None | str | Unset = UNSET
    business_unit: None | str | Unset = UNSET
    cost_center: None | str | Unset = UNSET
    criticality: AssetCriticality | None | Unset = UNSET
    criticality_tier: CriticalityTier | None | Unset = UNSET
    data_classification: DataClassification | None | Unset = UNSET
    compliance_scope: list[str] | None | Unset = UNSET
    environment: Environment | None | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    metadata: None | Unset | UpdateAssetRequestMetadataType0 = UNSET
    risk_score: float | None | Unset = UNSET
    finding_count: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_asset_request_metadata_type_0 import UpdateAssetRequestMetadataType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        asset_type: None | str | Unset
        if isinstance(self.asset_type, Unset):
            asset_type = UNSET
        else:
            asset_type = self.asset_type

        hostname: None | str | Unset
        if isinstance(self.hostname, Unset):
            hostname = UNSET
        else:
            hostname = self.hostname

        ip_address: None | str | Unset
        if isinstance(self.ip_address, Unset):
            ip_address = UNSET
        else:
            ip_address = self.ip_address

        cloud_provider: None | str | Unset
        if isinstance(self.cloud_provider, Unset):
            cloud_provider = UNSET
        else:
            cloud_provider = self.cloud_provider

        region: None | str | Unset
        if isinstance(self.region, Unset):
            region = UNSET
        else:
            region = self.region

        cloud_resource_id: None | str | Unset
        if isinstance(self.cloud_resource_id, Unset):
            cloud_resource_id = UNSET
        else:
            cloud_resource_id = self.cloud_resource_id

        owner_email: None | str | Unset
        if isinstance(self.owner_email, Unset):
            owner_email = UNSET
        else:
            owner_email = self.owner_email

        owner_name: None | str | Unset
        if isinstance(self.owner_name, Unset):
            owner_name = UNSET
        else:
            owner_name = self.owner_name

        team: None | str | Unset
        if isinstance(self.team, Unset):
            team = UNSET
        else:
            team = self.team

        business_unit: None | str | Unset
        if isinstance(self.business_unit, Unset):
            business_unit = UNSET
        else:
            business_unit = self.business_unit

        cost_center: None | str | Unset
        if isinstance(self.cost_center, Unset):
            cost_center = UNSET
        else:
            cost_center = self.cost_center

        criticality: None | str | Unset
        if isinstance(self.criticality, Unset):
            criticality = UNSET
        elif isinstance(self.criticality, AssetCriticality):
            criticality = self.criticality.value
        else:
            criticality = self.criticality

        criticality_tier: None | str | Unset
        if isinstance(self.criticality_tier, Unset):
            criticality_tier = UNSET
        elif isinstance(self.criticality_tier, CriticalityTier):
            criticality_tier = self.criticality_tier.value
        else:
            criticality_tier = self.criticality_tier

        data_classification: None | str | Unset
        if isinstance(self.data_classification, Unset):
            data_classification = UNSET
        elif isinstance(self.data_classification, DataClassification):
            data_classification = self.data_classification.value
        else:
            data_classification = self.data_classification

        compliance_scope: list[str] | None | Unset
        if isinstance(self.compliance_scope, Unset):
            compliance_scope = UNSET
        elif isinstance(self.compliance_scope, list):
            compliance_scope = self.compliance_scope

        else:
            compliance_scope = self.compliance_scope

        environment: None | str | Unset
        if isinstance(self.environment, Unset):
            environment = UNSET
        elif isinstance(self.environment, Environment):
            environment = self.environment.value
        else:
            environment = self.environment

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, UpdateAssetRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        risk_score: float | None | Unset
        if isinstance(self.risk_score, Unset):
            risk_score = UNSET
        else:
            risk_score = self.risk_score

        finding_count: int | None | Unset
        if isinstance(self.finding_count, Unset):
            finding_count = UNSET
        else:
            finding_count = self.finding_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if asset_type is not UNSET:
            field_dict["asset_type"] = asset_type
        if hostname is not UNSET:
            field_dict["hostname"] = hostname
        if ip_address is not UNSET:
            field_dict["ip_address"] = ip_address
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if region is not UNSET:
            field_dict["region"] = region
        if cloud_resource_id is not UNSET:
            field_dict["cloud_resource_id"] = cloud_resource_id
        if owner_email is not UNSET:
            field_dict["owner_email"] = owner_email
        if owner_name is not UNSET:
            field_dict["owner_name"] = owner_name
        if team is not UNSET:
            field_dict["team"] = team
        if business_unit is not UNSET:
            field_dict["business_unit"] = business_unit
        if cost_center is not UNSET:
            field_dict["cost_center"] = cost_center
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if criticality_tier is not UNSET:
            field_dict["criticality_tier"] = criticality_tier
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification
        if compliance_scope is not UNSET:
            field_dict["compliance_scope"] = compliance_scope
        if environment is not UNSET:
            field_dict["environment"] = environment
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if finding_count is not UNSET:
            field_dict["finding_count"] = finding_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_asset_request_metadata_type_0 import UpdateAssetRequestMetadataType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_asset_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_type = _parse_asset_type(d.pop("asset_type", UNSET))

        def _parse_hostname(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        hostname = _parse_hostname(d.pop("hostname", UNSET))

        def _parse_ip_address(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ip_address = _parse_ip_address(d.pop("ip_address", UNSET))

        def _parse_cloud_provider(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cloud_provider = _parse_cloud_provider(d.pop("cloud_provider", UNSET))

        def _parse_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        region = _parse_region(d.pop("region", UNSET))

        def _parse_cloud_resource_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cloud_resource_id = _parse_cloud_resource_id(d.pop("cloud_resource_id", UNSET))

        def _parse_owner_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_email = _parse_owner_email(d.pop("owner_email", UNSET))

        def _parse_owner_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_name = _parse_owner_name(d.pop("owner_name", UNSET))

        def _parse_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        team = _parse_team(d.pop("team", UNSET))

        def _parse_business_unit(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        business_unit = _parse_business_unit(d.pop("business_unit", UNSET))

        def _parse_cost_center(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cost_center = _parse_cost_center(d.pop("cost_center", UNSET))

        def _parse_criticality(data: object) -> AssetCriticality | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                criticality_type_0 = AssetCriticality(data)

                return criticality_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AssetCriticality | None | Unset, data)

        criticality = _parse_criticality(d.pop("criticality", UNSET))

        def _parse_criticality_tier(data: object) -> CriticalityTier | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                criticality_tier_type_0 = CriticalityTier(data)

                return criticality_tier_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CriticalityTier | None | Unset, data)

        criticality_tier = _parse_criticality_tier(d.pop("criticality_tier", UNSET))

        def _parse_data_classification(data: object) -> DataClassification | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                data_classification_type_0 = DataClassification(data)

                return data_classification_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DataClassification | None | Unset, data)

        data_classification = _parse_data_classification(d.pop("data_classification", UNSET))

        def _parse_compliance_scope(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                compliance_scope_type_0 = cast(list[str], data)

                return compliance_scope_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        compliance_scope = _parse_compliance_scope(d.pop("compliance_scope", UNSET))

        def _parse_environment(data: object) -> Environment | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                environment_type_0 = Environment(data)

                return environment_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(Environment | None | Unset, data)

        environment = _parse_environment(d.pop("environment", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_metadata(data: object) -> None | Unset | UpdateAssetRequestMetadataType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = UpdateAssetRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateAssetRequestMetadataType0, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        def _parse_risk_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        risk_score = _parse_risk_score(d.pop("risk_score", UNSET))

        def _parse_finding_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        finding_count = _parse_finding_count(d.pop("finding_count", UNSET))

        update_asset_request = cls(
            name=name,
            asset_type=asset_type,
            hostname=hostname,
            ip_address=ip_address,
            cloud_provider=cloud_provider,
            region=region,
            cloud_resource_id=cloud_resource_id,
            owner_email=owner_email,
            owner_name=owner_name,
            team=team,
            business_unit=business_unit,
            cost_center=cost_center,
            criticality=criticality,
            criticality_tier=criticality_tier,
            data_classification=data_classification,
            compliance_scope=compliance_scope,
            environment=environment,
            tags=tags,
            metadata=metadata,
            risk_score=risk_score,
            finding_count=finding_count,
        )

        update_asset_request.additional_properties = d
        return update_asset_request

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
