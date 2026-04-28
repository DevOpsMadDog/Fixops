from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ContainerCreate")


@_attrs_define
class ContainerCreate:
    """
    Attributes:
        container_id (str):
        image_name (str):
        org_id (str | Unset):  Default: 'default'.
        image_tag (str | Unset):  Default: 'latest'.
        pod_name (str | Unset):  Default: ''.
        namespace (str | Unset):  Default: 'default'.
        cluster (str | Unset):  Default: ''.
        runtime_status (str | Unset):  Default: 'running'.
        privileged (bool | Unset):  Default: False.
        host_network (bool | Unset):  Default: False.
        security_score (int | Unset):  Default: 100.
    """

    container_id: str
    image_name: str
    org_id: str | Unset = "default"
    image_tag: str | Unset = "latest"
    pod_name: str | Unset = ""
    namespace: str | Unset = "default"
    cluster: str | Unset = ""
    runtime_status: str | Unset = "running"
    privileged: bool | Unset = False
    host_network: bool | Unset = False
    security_score: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        container_id = self.container_id

        image_name = self.image_name

        org_id = self.org_id

        image_tag = self.image_tag

        pod_name = self.pod_name

        namespace = self.namespace

        cluster = self.cluster

        runtime_status = self.runtime_status

        privileged = self.privileged

        host_network = self.host_network

        security_score = self.security_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "container_id": container_id,
                "image_name": image_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if image_tag is not UNSET:
            field_dict["image_tag"] = image_tag
        if pod_name is not UNSET:
            field_dict["pod_name"] = pod_name
        if namespace is not UNSET:
            field_dict["namespace"] = namespace
        if cluster is not UNSET:
            field_dict["cluster"] = cluster
        if runtime_status is not UNSET:
            field_dict["runtime_status"] = runtime_status
        if privileged is not UNSET:
            field_dict["privileged"] = privileged
        if host_network is not UNSET:
            field_dict["host_network"] = host_network
        if security_score is not UNSET:
            field_dict["security_score"] = security_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        container_id = d.pop("container_id")

        image_name = d.pop("image_name")

        org_id = d.pop("org_id", UNSET)

        image_tag = d.pop("image_tag", UNSET)

        pod_name = d.pop("pod_name", UNSET)

        namespace = d.pop("namespace", UNSET)

        cluster = d.pop("cluster", UNSET)

        runtime_status = d.pop("runtime_status", UNSET)

        privileged = d.pop("privileged", UNSET)

        host_network = d.pop("host_network", UNSET)

        security_score = d.pop("security_score", UNSET)

        container_create = cls(
            container_id=container_id,
            image_name=image_name,
            org_id=org_id,
            image_tag=image_tag,
            pod_name=pod_name,
            namespace=namespace,
            cluster=cluster,
            runtime_status=runtime_status,
            privileged=privileged,
            host_network=host_network,
            security_score=security_score,
        )

        container_create.additional_properties = d
        return container_create

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
