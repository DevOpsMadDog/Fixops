from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.auth_provider import AuthProvider
from ..models.sso_status import SSOStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sso_config_create_metadata import SSOConfigCreateMetadata


T = TypeVar("T", bound="SSOConfigCreate")


@_attrs_define
class SSOConfigCreate:
    """Request model for creating SSO configuration.

    Attributes:
        name (str):
        provider (AuthProvider): Authentication provider types.
        status (SSOStatus | Unset): SSO configuration status.
        metadata (SSOConfigCreateMetadata | Unset):
        entity_id (None | str | Unset):
        sso_url (None | str | Unset):
        certificate (None | str | Unset):
    """

    name: str
    provider: AuthProvider
    status: SSOStatus | Unset = UNSET
    metadata: SSOConfigCreateMetadata | Unset = UNSET
    entity_id: None | str | Unset = UNSET
    sso_url: None | str | Unset = UNSET
    certificate: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        provider = self.provider.value

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        entity_id: None | str | Unset
        if isinstance(self.entity_id, Unset):
            entity_id = UNSET
        else:
            entity_id = self.entity_id

        sso_url: None | str | Unset
        if isinstance(self.sso_url, Unset):
            sso_url = UNSET
        else:
            sso_url = self.sso_url

        certificate: None | str | Unset
        if isinstance(self.certificate, Unset):
            certificate = UNSET
        else:
            certificate = self.certificate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "provider": provider,
            }
        )
        if status is not UNSET:
            field_dict["status"] = status
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if entity_id is not UNSET:
            field_dict["entity_id"] = entity_id
        if sso_url is not UNSET:
            field_dict["sso_url"] = sso_url
        if certificate is not UNSET:
            field_dict["certificate"] = certificate

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sso_config_create_metadata import SSOConfigCreateMetadata

        d = dict(src_dict)
        name = d.pop("name")

        provider = AuthProvider(d.pop("provider"))

        _status = d.pop("status", UNSET)
        status: SSOStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = SSOStatus(_status)

        _metadata = d.pop("metadata", UNSET)
        metadata: SSOConfigCreateMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = SSOConfigCreateMetadata.from_dict(_metadata)

        def _parse_entity_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        entity_id = _parse_entity_id(d.pop("entity_id", UNSET))

        def _parse_sso_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sso_url = _parse_sso_url(d.pop("sso_url", UNSET))

        def _parse_certificate(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        certificate = _parse_certificate(d.pop("certificate", UNSET))

        sso_config_create = cls(
            name=name,
            provider=provider,
            status=status,
            metadata=metadata,
            entity_id=entity_id,
            sso_url=sso_url,
            certificate=certificate,
        )

        sso_config_create.additional_properties = d
        return sso_config_create

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
