from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeployPatchIn")


@_attrs_define
class DeployPatchIn:
    """
    Attributes:
        patch_id (str):
        asset_id (str):
        asset_name (str | Unset):  Default: ''.
        deployed_by (str | Unset):  Default: ''.
        deployment_type (str | Unset):  Default: 'manual'.
    """

    patch_id: str
    asset_id: str
    asset_name: str | Unset = ""
    deployed_by: str | Unset = ""
    deployment_type: str | Unset = "manual"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        patch_id = self.patch_id

        asset_id = self.asset_id

        asset_name = self.asset_name

        deployed_by = self.deployed_by

        deployment_type = self.deployment_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "patch_id": patch_id,
                "asset_id": asset_id,
            }
        )
        if asset_name is not UNSET:
            field_dict["asset_name"] = asset_name
        if deployed_by is not UNSET:
            field_dict["deployed_by"] = deployed_by
        if deployment_type is not UNSET:
            field_dict["deployment_type"] = deployment_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        patch_id = d.pop("patch_id")

        asset_id = d.pop("asset_id")

        asset_name = d.pop("asset_name", UNSET)

        deployed_by = d.pop("deployed_by", UNSET)

        deployment_type = d.pop("deployment_type", UNSET)

        deploy_patch_in = cls(
            patch_id=patch_id,
            asset_id=asset_id,
            asset_name=asset_name,
            deployed_by=deployed_by,
            deployment_type=deployment_type,
        )

        deploy_patch_in.additional_properties = d
        return deploy_patch_in

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
