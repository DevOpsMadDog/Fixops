from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.cloud_provider import CloudProvider
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.check_resource_request_actual_config import CheckResourceRequestActualConfig


T = TypeVar("T", bound="CheckResourceRequest")


@_attrs_define
class CheckResourceRequest:
    """
    Attributes:
        resource_id (str): Unique identifier of the resource
        resource_type (str): Resource type (e.g. s3_bucket, iam_user)
        actual_config (CheckResourceRequestActualConfig): Current resource configuration
        provider (CloudProvider):
        org_id (str | Unset): Organisation identifier Default: 'default'.
    """

    resource_id: str
    resource_type: str
    actual_config: CheckResourceRequestActualConfig
    provider: CloudProvider
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resource_id = self.resource_id

        resource_type = self.resource_type

        actual_config = self.actual_config.to_dict()

        provider = self.provider.value

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resource_id": resource_id,
                "resource_type": resource_type,
                "actual_config": actual_config,
                "provider": provider,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.check_resource_request_actual_config import CheckResourceRequestActualConfig

        d = dict(src_dict)
        resource_id = d.pop("resource_id")

        resource_type = d.pop("resource_type")

        actual_config = CheckResourceRequestActualConfig.from_dict(d.pop("actual_config"))

        provider = CloudProvider(d.pop("provider"))

        org_id = d.pop("org_id", UNSET)

        check_resource_request = cls(
            resource_id=resource_id,
            resource_type=resource_type,
            actual_config=actual_config,
            provider=provider,
            org_id=org_id,
        )

        check_resource_request.additional_properties = d
        return check_resource_request

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
