from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterClusterRequest")


@_attrs_define
class RegisterClusterRequest:
    """
    Attributes:
        cluster_name (str | Unset):  Default: 'unnamed-cluster'.
        provider (str | Unset):  Default: 'eks'.
        k8s_version (str | Unset):  Default: '1.28'.
        node_count (int | Unset):  Default: 1.
        namespace_count (int | Unset):  Default: 1.
    """

    cluster_name: str | Unset = "unnamed-cluster"
    provider: str | Unset = "eks"
    k8s_version: str | Unset = "1.28"
    node_count: int | Unset = 1
    namespace_count: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cluster_name = self.cluster_name

        provider = self.provider

        k8s_version = self.k8s_version

        node_count = self.node_count

        namespace_count = self.namespace_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cluster_name is not UNSET:
            field_dict["cluster_name"] = cluster_name
        if provider is not UNSET:
            field_dict["provider"] = provider
        if k8s_version is not UNSET:
            field_dict["k8s_version"] = k8s_version
        if node_count is not UNSET:
            field_dict["node_count"] = node_count
        if namespace_count is not UNSET:
            field_dict["namespace_count"] = namespace_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cluster_name = d.pop("cluster_name", UNSET)

        provider = d.pop("provider", UNSET)

        k8s_version = d.pop("k8s_version", UNSET)

        node_count = d.pop("node_count", UNSET)

        namespace_count = d.pop("namespace_count", UNSET)

        register_cluster_request = cls(
            cluster_name=cluster_name,
            provider=provider,
            k8s_version=k8s_version,
            node_count=node_count,
            namespace_count=namespace_count,
        )

        register_cluster_request.additional_properties = d
        return register_cluster_request

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
