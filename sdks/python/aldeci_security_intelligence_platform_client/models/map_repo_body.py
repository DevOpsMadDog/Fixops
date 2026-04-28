from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MapRepoBody")


@_attrs_define
class MapRepoBody:
    """
    Attributes:
        repo_path (str): Absolute path to repo on disk
        service_name (None | str | Unset): Override service name (defaults to repo dir name)
        criticality (str | Unset): critical | high | medium | low Default: 'medium'.
    """

    repo_path: str
    service_name: None | str | Unset = UNSET
    criticality: str | Unset = "medium"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_path = self.repo_path

        service_name: None | str | Unset
        if isinstance(self.service_name, Unset):
            service_name = UNSET
        else:
            service_name = self.service_name

        criticality = self.criticality

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_path": repo_path,
            }
        )
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if criticality is not UNSET:
            field_dict["criticality"] = criticality

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_path = d.pop("repo_path")

        def _parse_service_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        service_name = _parse_service_name(d.pop("service_name", UNSET))

        criticality = d.pop("criticality", UNSET)

        map_repo_body = cls(
            repo_path=repo_path,
            service_name=service_name,
            criticality=criticality,
        )

        map_repo_body.additional_properties = d
        return map_repo_body

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
