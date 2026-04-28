from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterDeploymentRequest")


@_attrs_define
class RegisterDeploymentRequest:
    """
    Attributes:
        artifact_id (str):
        environment (str | Unset):  Default: 'production'.
        deployed_by (str | Unset):  Default: 'ci-system'.
        k8s_namespace (None | str | Unset):
        k8s_deployment (None | str | Unset):
        k8s_pod_count (int | Unset):  Default: 0.
        cloud_provider (str | Unset):  Default: 'unknown'.
        cloud_region (None | str | Unset):
        cloud_service (None | str | Unset):
        cloud_instance_ids (list[str] | Unset):
        internet_facing (bool | Unset):  Default: False.
        previous_deployment_id (None | str | Unset):
    """

    artifact_id: str
    environment: str | Unset = "production"
    deployed_by: str | Unset = "ci-system"
    k8s_namespace: None | str | Unset = UNSET
    k8s_deployment: None | str | Unset = UNSET
    k8s_pod_count: int | Unset = 0
    cloud_provider: str | Unset = "unknown"
    cloud_region: None | str | Unset = UNSET
    cloud_service: None | str | Unset = UNSET
    cloud_instance_ids: list[str] | Unset = UNSET
    internet_facing: bool | Unset = False
    previous_deployment_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        artifact_id = self.artifact_id

        environment = self.environment

        deployed_by = self.deployed_by

        k8s_namespace: None | str | Unset
        if isinstance(self.k8s_namespace, Unset):
            k8s_namespace = UNSET
        else:
            k8s_namespace = self.k8s_namespace

        k8s_deployment: None | str | Unset
        if isinstance(self.k8s_deployment, Unset):
            k8s_deployment = UNSET
        else:
            k8s_deployment = self.k8s_deployment

        k8s_pod_count = self.k8s_pod_count

        cloud_provider = self.cloud_provider

        cloud_region: None | str | Unset
        if isinstance(self.cloud_region, Unset):
            cloud_region = UNSET
        else:
            cloud_region = self.cloud_region

        cloud_service: None | str | Unset
        if isinstance(self.cloud_service, Unset):
            cloud_service = UNSET
        else:
            cloud_service = self.cloud_service

        cloud_instance_ids: list[str] | Unset = UNSET
        if not isinstance(self.cloud_instance_ids, Unset):
            cloud_instance_ids = self.cloud_instance_ids

        internet_facing = self.internet_facing

        previous_deployment_id: None | str | Unset
        if isinstance(self.previous_deployment_id, Unset):
            previous_deployment_id = UNSET
        else:
            previous_deployment_id = self.previous_deployment_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "artifact_id": artifact_id,
            }
        )
        if environment is not UNSET:
            field_dict["environment"] = environment
        if deployed_by is not UNSET:
            field_dict["deployed_by"] = deployed_by
        if k8s_namespace is not UNSET:
            field_dict["k8s_namespace"] = k8s_namespace
        if k8s_deployment is not UNSET:
            field_dict["k8s_deployment"] = k8s_deployment
        if k8s_pod_count is not UNSET:
            field_dict["k8s_pod_count"] = k8s_pod_count
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if cloud_region is not UNSET:
            field_dict["cloud_region"] = cloud_region
        if cloud_service is not UNSET:
            field_dict["cloud_service"] = cloud_service
        if cloud_instance_ids is not UNSET:
            field_dict["cloud_instance_ids"] = cloud_instance_ids
        if internet_facing is not UNSET:
            field_dict["internet_facing"] = internet_facing
        if previous_deployment_id is not UNSET:
            field_dict["previous_deployment_id"] = previous_deployment_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        artifact_id = d.pop("artifact_id")

        environment = d.pop("environment", UNSET)

        deployed_by = d.pop("deployed_by", UNSET)

        def _parse_k8s_namespace(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        k8s_namespace = _parse_k8s_namespace(d.pop("k8s_namespace", UNSET))

        def _parse_k8s_deployment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        k8s_deployment = _parse_k8s_deployment(d.pop("k8s_deployment", UNSET))

        k8s_pod_count = d.pop("k8s_pod_count", UNSET)

        cloud_provider = d.pop("cloud_provider", UNSET)

        def _parse_cloud_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cloud_region = _parse_cloud_region(d.pop("cloud_region", UNSET))

        def _parse_cloud_service(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cloud_service = _parse_cloud_service(d.pop("cloud_service", UNSET))

        cloud_instance_ids = cast(list[str], d.pop("cloud_instance_ids", UNSET))

        internet_facing = d.pop("internet_facing", UNSET)

        def _parse_previous_deployment_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        previous_deployment_id = _parse_previous_deployment_id(d.pop("previous_deployment_id", UNSET))

        register_deployment_request = cls(
            artifact_id=artifact_id,
            environment=environment,
            deployed_by=deployed_by,
            k8s_namespace=k8s_namespace,
            k8s_deployment=k8s_deployment,
            k8s_pod_count=k8s_pod_count,
            cloud_provider=cloud_provider,
            cloud_region=cloud_region,
            cloud_service=cloud_service,
            cloud_instance_ids=cloud_instance_ids,
            internet_facing=internet_facing,
            previous_deployment_id=previous_deployment_id,
        )

        register_deployment_request.additional_properties = d
        return register_deployment_request

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
