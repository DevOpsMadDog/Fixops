from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ServiceMappingCreate")


@_attrs_define
class ServiceMappingCreate:
    """
    Attributes:
        org_id (str):
        service_name (str):
        repo_ref (str):
        deploy_ref (str | Unset):  Default: ''.
    """

    org_id: str
    service_name: str
    repo_ref: str
    deploy_ref: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        service_name = self.service_name

        repo_ref = self.repo_ref

        deploy_ref = self.deploy_ref

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "service_name": service_name,
                "repo_ref": repo_ref,
            }
        )
        if deploy_ref is not UNSET:
            field_dict["deploy_ref"] = deploy_ref

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        service_name = d.pop("service_name")

        repo_ref = d.pop("repo_ref")

        deploy_ref = d.pop("deploy_ref", UNSET)

        service_mapping_create = cls(
            org_id=org_id,
            service_name=service_name,
            repo_ref=repo_ref,
            deploy_ref=deploy_ref,
        )

        service_mapping_create.additional_properties = d
        return service_mapping_create

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
