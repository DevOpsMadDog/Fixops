from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.integration_status import IntegrationStatus
from ..models.integration_type import IntegrationType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.integration_create_config import IntegrationCreateConfig


T = TypeVar("T", bound="IntegrationCreate")


@_attrs_define
class IntegrationCreate:
    """Request model for creating an integration.

    Attributes:
        name (str):
        integration_type (IntegrationType): Integration types.
        status (IntegrationStatus | Unset): Integration status.
        config (IntegrationCreateConfig | Unset):
    """

    name: str
    integration_type: IntegrationType
    status: IntegrationStatus | Unset = UNSET
    config: IntegrationCreateConfig | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        integration_type = self.integration_type.value

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "integration_type": integration_type,
            }
        )
        if status is not UNSET:
            field_dict["status"] = status
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.integration_create_config import IntegrationCreateConfig

        d = dict(src_dict)
        name = d.pop("name")

        integration_type = IntegrationType(d.pop("integration_type"))

        _status = d.pop("status", UNSET)
        status: IntegrationStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = IntegrationStatus(_status)

        _config = d.pop("config", UNSET)
        config: IntegrationCreateConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = IntegrationCreateConfig.from_dict(_config)

        integration_create = cls(
            name=name,
            integration_type=integration_type,
            status=status,
            config=config,
        )

        integration_create.additional_properties = d
        return integration_create

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
