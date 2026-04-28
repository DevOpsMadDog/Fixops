from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArchitectureDetectRequest")


@_attrs_define
class ArchitectureDetectRequest:
    """
    Attributes:
        repo_path (str):
        include_files_glob (list[str] | Unset):
        detect_layers (bool | Unset):  Default: True.
        detect_databases (bool | Unset):  Default: True.
        detect_apis (bool | Unset):  Default: True.
    """

    repo_path: str
    include_files_glob: list[str] | Unset = UNSET
    detect_layers: bool | Unset = True
    detect_databases: bool | Unset = True
    detect_apis: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_path = self.repo_path

        include_files_glob: list[str] | Unset = UNSET
        if not isinstance(self.include_files_glob, Unset):
            include_files_glob = self.include_files_glob

        detect_layers = self.detect_layers

        detect_databases = self.detect_databases

        detect_apis = self.detect_apis

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_path": repo_path,
            }
        )
        if include_files_glob is not UNSET:
            field_dict["include_files_glob"] = include_files_glob
        if detect_layers is not UNSET:
            field_dict["detect_layers"] = detect_layers
        if detect_databases is not UNSET:
            field_dict["detect_databases"] = detect_databases
        if detect_apis is not UNSET:
            field_dict["detect_apis"] = detect_apis

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_path = d.pop("repo_path")

        include_files_glob = cast(list[str], d.pop("include_files_glob", UNSET))

        detect_layers = d.pop("detect_layers", UNSET)

        detect_databases = d.pop("detect_databases", UNSET)

        detect_apis = d.pop("detect_apis", UNSET)

        architecture_detect_request = cls(
            repo_path=repo_path,
            include_files_glob=include_files_glob,
            detect_layers=detect_layers,
            detect_databases=detect_databases,
            detect_apis=detect_apis,
        )

        architecture_detect_request.additional_properties = d
        return architecture_detect_request

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
