from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.asset_criticality import AssetCriticality
from ..models.asset_lifecycle import AssetLifecycle
from ..models.criticality_tier import CriticalityTier
from ..models.data_classification import DataClassification
from ..models.environment import Environment
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_asset_request_metadata import RegisterAssetRequestMetadata


T = TypeVar("T", bound="RegisterAssetRequest")


@_attrs_define
class RegisterAssetRequest:
    """
    Attributes:
        name (str): Asset name or identifier
        asset_type (str): Asset type (server, container, cloud_resource, application, database, api, repository,
            network_device, user, certificate, etc.)
        hostname (None | str | Unset):
        ip_address (None | str | Unset):
        cloud_provider (None | str | Unset): aws, gcp, azure, on-prem
        region (None | str | Unset):
        cloud_resource_id (None | str | Unset): ARN, resource ID, etc.
        owner_email (None | str | Unset):
        owner_name (None | str | Unset):
        team (None | str | Unset):
        business_unit (None | str | Unset):
        cost_center (None | str | Unset):
        criticality (AssetCriticality | Unset):
        criticality_tier (CriticalityTier | Unset): Business criticality tier — T1 (most critical) to T4 (least
            critical).
        data_classification (DataClassification | Unset):
        compliance_scope (list[str] | Unset):
        environment (Environment | Unset):
        lifecycle (AssetLifecycle | Unset):
        discovery_source (None | str | Unset):
        tags (list[str] | Unset):
        metadata (RegisterAssetRequestMetadata | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    name: str
    asset_type: str
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
    criticality: AssetCriticality | Unset = UNSET
    criticality_tier: CriticalityTier | Unset = UNSET
    data_classification: DataClassification | Unset = UNSET
    compliance_scope: list[str] | Unset = UNSET
    environment: Environment | Unset = UNSET
    lifecycle: AssetLifecycle | Unset = UNSET
    discovery_source: None | str | Unset = UNSET
    tags: list[str] | Unset = UNSET
    metadata: RegisterAssetRequestMetadata | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

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

        criticality: str | Unset = UNSET
        if not isinstance(self.criticality, Unset):
            criticality = self.criticality.value

        criticality_tier: str | Unset = UNSET
        if not isinstance(self.criticality_tier, Unset):
            criticality_tier = self.criticality_tier.value

        data_classification: str | Unset = UNSET
        if not isinstance(self.data_classification, Unset):
            data_classification = self.data_classification.value

        compliance_scope: list[str] | Unset = UNSET
        if not isinstance(self.compliance_scope, Unset):
            compliance_scope = self.compliance_scope

        environment: str | Unset = UNSET
        if not isinstance(self.environment, Unset):
            environment = self.environment.value

        lifecycle: str | Unset = UNSET
        if not isinstance(self.lifecycle, Unset):
            lifecycle = self.lifecycle.value

        discovery_source: None | str | Unset
        if isinstance(self.discovery_source, Unset):
            discovery_source = UNSET
        else:
            discovery_source = self.discovery_source

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "asset_type": asset_type,
            }
        )
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
        if lifecycle is not UNSET:
            field_dict["lifecycle"] = lifecycle
        if discovery_source is not UNSET:
            field_dict["discovery_source"] = discovery_source
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_asset_request_metadata import RegisterAssetRequestMetadata

        d = dict(src_dict)
        name = d.pop("name")

        asset_type = d.pop("asset_type")

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

        _criticality = d.pop("criticality", UNSET)
        criticality: AssetCriticality | Unset
        if isinstance(_criticality, Unset):
            criticality = UNSET
        else:
            criticality = AssetCriticality(_criticality)

        _criticality_tier = d.pop("criticality_tier", UNSET)
        criticality_tier: CriticalityTier | Unset
        if isinstance(_criticality_tier, Unset):
            criticality_tier = UNSET
        else:
            criticality_tier = CriticalityTier(_criticality_tier)

        _data_classification = d.pop("data_classification", UNSET)
        data_classification: DataClassification | Unset
        if isinstance(_data_classification, Unset):
            data_classification = UNSET
        else:
            data_classification = DataClassification(_data_classification)

        compliance_scope = cast(list[str], d.pop("compliance_scope", UNSET))

        _environment = d.pop("environment", UNSET)
        environment: Environment | Unset
        if isinstance(_environment, Unset):
            environment = UNSET
        else:
            environment = Environment(_environment)

        _lifecycle = d.pop("lifecycle", UNSET)
        lifecycle: AssetLifecycle | Unset
        if isinstance(_lifecycle, Unset):
            lifecycle = UNSET
        else:
            lifecycle = AssetLifecycle(_lifecycle)

        def _parse_discovery_source(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovery_source = _parse_discovery_source(d.pop("discovery_source", UNSET))

        tags = cast(list[str], d.pop("tags", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: RegisterAssetRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = RegisterAssetRequestMetadata.from_dict(_metadata)

        org_id = d.pop("org_id", UNSET)

        register_asset_request = cls(
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
            lifecycle=lifecycle,
            discovery_source=discovery_source,
            tags=tags,
            metadata=metadata,
            org_id=org_id,
        )

        register_asset_request.additional_properties = d
        return register_asset_request

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
