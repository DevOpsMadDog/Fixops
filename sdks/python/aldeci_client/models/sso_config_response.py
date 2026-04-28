from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.sso_config_response_metadata import SSOConfigResponseMetadata


T = TypeVar("T", bound="SSOConfigResponse")


@_attrs_define
class SSOConfigResponse:
    """Response model for SSO configuration.

    Attributes:
        id (str):
        name (str):
        provider (str):
        status (str):
        metadata (SSOConfigResponseMetadata):
        entity_id (None | str):
        sso_url (None | str):
        certificate (None | str):
        created_at (str):
        updated_at (str):
    """

    id: str
    name: str
    provider: str
    status: str
    metadata: SSOConfigResponseMetadata
    entity_id: None | str
    sso_url: None | str
    certificate: None | str
    created_at: str
    updated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        provider = self.provider

        status = self.status

        metadata = self.metadata.to_dict()

        entity_id: None | str
        entity_id = self.entity_id

        sso_url: None | str
        sso_url = self.sso_url

        certificate: None | str
        certificate = self.certificate

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "provider": provider,
                "status": status,
                "metadata": metadata,
                "entity_id": entity_id,
                "sso_url": sso_url,
                "certificate": certificate,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sso_config_response_metadata import SSOConfigResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        provider = d.pop("provider")

        status = d.pop("status")

        metadata = SSOConfigResponseMetadata.from_dict(d.pop("metadata"))

        def _parse_entity_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        entity_id = _parse_entity_id(d.pop("entity_id"))

        def _parse_sso_url(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        sso_url = _parse_sso_url(d.pop("sso_url"))

        def _parse_certificate(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        certificate = _parse_certificate(d.pop("certificate"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        sso_config_response = cls(
            id=id,
            name=name,
            provider=provider,
            status=status,
            metadata=metadata,
            entity_id=entity_id,
            sso_url=sso_url,
            certificate=certificate,
            created_at=created_at,
            updated_at=updated_at,
        )

        sso_config_response.additional_properties = d
        return sso_config_response

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
