from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.cloud_provider import CloudProvider

if TYPE_CHECKING:
    from ..models.batch_resource_actual_config import BatchResourceActualConfig


T = TypeVar("T", bound="BatchResource")


@_attrs_define
class BatchResource:
    """
    Attributes:
        resource_id (str):
        resource_type (str):
        actual_config (BatchResourceActualConfig):
        provider (CloudProvider):
    """

    resource_id: str
    resource_type: str
    actual_config: BatchResourceActualConfig
    provider: CloudProvider
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resource_id = self.resource_id

        resource_type = self.resource_type

        actual_config = self.actual_config.to_dict()

        provider = self.provider.value

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

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_resource_actual_config import BatchResourceActualConfig

        d = dict(src_dict)
        resource_id = d.pop("resource_id")

        resource_type = d.pop("resource_type")

        actual_config = BatchResourceActualConfig.from_dict(d.pop("actual_config"))

        provider = CloudProvider(d.pop("provider"))

        batch_resource = cls(
            resource_id=resource_id,
            resource_type=resource_type,
            actual_config=actual_config,
            provider=provider,
        )

        batch_resource.additional_properties = d
        return batch_resource

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
