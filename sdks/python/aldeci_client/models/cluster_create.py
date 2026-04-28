from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ClusterCreate")


@_attrs_define
class ClusterCreate:
    """
    Attributes:
        name (str):
        runtime (str | Unset):  Default: 'docker'.
        version (str | Unset):  Default: ''.
        node_count (int | Unset):  Default: 0.
        namespace_count (int | Unset):  Default: 0.
        last_scanned (None | str | Unset):
    """

    name: str
    runtime: str | Unset = "docker"
    version: str | Unset = ""
    node_count: int | Unset = 0
    namespace_count: int | Unset = 0
    last_scanned: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        runtime = self.runtime

        version = self.version

        node_count = self.node_count

        namespace_count = self.namespace_count

        last_scanned: None | str | Unset
        if isinstance(self.last_scanned, Unset):
            last_scanned = UNSET
        else:
            last_scanned = self.last_scanned

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if runtime is not UNSET:
            field_dict["runtime"] = runtime
        if version is not UNSET:
            field_dict["version"] = version
        if node_count is not UNSET:
            field_dict["node_count"] = node_count
        if namespace_count is not UNSET:
            field_dict["namespace_count"] = namespace_count
        if last_scanned is not UNSET:
            field_dict["last_scanned"] = last_scanned

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        runtime = d.pop("runtime", UNSET)

        version = d.pop("version", UNSET)

        node_count = d.pop("node_count", UNSET)

        namespace_count = d.pop("namespace_count", UNSET)

        def _parse_last_scanned(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_scanned = _parse_last_scanned(d.pop("last_scanned", UNSET))

        cluster_create = cls(
            name=name,
            runtime=runtime,
            version=version,
            node_count=node_count,
            namespace_count=namespace_count,
            last_scanned=last_scanned,
        )

        cluster_create.additional_properties = d
        return cluster_create

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
