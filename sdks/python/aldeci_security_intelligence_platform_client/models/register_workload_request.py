from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterWorkloadRequest")


@_attrs_define
class RegisterWorkloadRequest:
    """
    Attributes:
        name (str):
        workload_type (str | Unset):  Default: 'vm'.
        cloud_provider (str | Unset):  Default: 'aws'.
        region (str | Unset):  Default: ''.
        image_name (str | Unset):  Default: ''.
        image_hash (str | Unset):  Default: ''.
        running (bool | Unset):  Default: True.
        privileged (bool | Unset):  Default: False.
    """

    name: str
    workload_type: str | Unset = "vm"
    cloud_provider: str | Unset = "aws"
    region: str | Unset = ""
    image_name: str | Unset = ""
    image_hash: str | Unset = ""
    running: bool | Unset = True
    privileged: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        workload_type = self.workload_type

        cloud_provider = self.cloud_provider

        region = self.region

        image_name = self.image_name

        image_hash = self.image_hash

        running = self.running

        privileged = self.privileged

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if workload_type is not UNSET:
            field_dict["workload_type"] = workload_type
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if region is not UNSET:
            field_dict["region"] = region
        if image_name is not UNSET:
            field_dict["image_name"] = image_name
        if image_hash is not UNSET:
            field_dict["image_hash"] = image_hash
        if running is not UNSET:
            field_dict["running"] = running
        if privileged is not UNSET:
            field_dict["privileged"] = privileged

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        workload_type = d.pop("workload_type", UNSET)

        cloud_provider = d.pop("cloud_provider", UNSET)

        region = d.pop("region", UNSET)

        image_name = d.pop("image_name", UNSET)

        image_hash = d.pop("image_hash", UNSET)

        running = d.pop("running", UNSET)

        privileged = d.pop("privileged", UNSET)

        register_workload_request = cls(
            name=name,
            workload_type=workload_type,
            cloud_provider=cloud_provider,
            region=region,
            image_name=image_name,
            image_hash=image_hash,
            running=running,
            privileged=privileged,
        )

        register_workload_request.additional_properties = d
        return register_workload_request

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
