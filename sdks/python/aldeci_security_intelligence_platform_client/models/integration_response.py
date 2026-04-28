from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.integration_response_config import IntegrationResponseConfig


T = TypeVar("T", bound="IntegrationResponse")


@_attrs_define
class IntegrationResponse:
    """Response model for an integration.

    Attributes:
        id (str):
        name (str):
        integration_type (str):
        status (str):
        config (IntegrationResponseConfig):
        last_sync_at (None | str):
        last_sync_status (None | str):
        created_at (str):
        updated_at (str):
    """

    id: str
    name: str
    integration_type: str
    status: str
    config: IntegrationResponseConfig
    last_sync_at: None | str
    last_sync_status: None | str
    created_at: str
    updated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        integration_type = self.integration_type

        status = self.status

        config = self.config.to_dict()

        last_sync_at: None | str
        last_sync_at = self.last_sync_at

        last_sync_status: None | str
        last_sync_status = self.last_sync_status

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "integration_type": integration_type,
                "status": status,
                "config": config,
                "last_sync_at": last_sync_at,
                "last_sync_status": last_sync_status,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.integration_response_config import IntegrationResponseConfig

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        integration_type = d.pop("integration_type")

        status = d.pop("status")

        config = IntegrationResponseConfig.from_dict(d.pop("config"))

        def _parse_last_sync_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_sync_at = _parse_last_sync_at(d.pop("last_sync_at"))

        def _parse_last_sync_status(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        last_sync_status = _parse_last_sync_status(d.pop("last_sync_status"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        integration_response = cls(
            id=id,
            name=name,
            integration_type=integration_type,
            status=status,
            config=config,
            last_sync_at=last_sync_at,
            last_sync_status=last_sync_status,
            created_at=created_at,
            updated_at=updated_at,
        )

        integration_response.additional_properties = d
        return integration_response

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
