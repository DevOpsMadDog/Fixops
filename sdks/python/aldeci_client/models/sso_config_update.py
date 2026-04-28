from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.sso_status import SSOStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sso_config_update_metadata_type_0 import SSOConfigUpdateMetadataType0


T = TypeVar("T", bound="SSOConfigUpdate")


@_attrs_define
class SSOConfigUpdate:
    """Request model for updating SSO configuration.

    Attributes:
        name (None | str | Unset):
        status (None | SSOStatus | Unset):
        metadata (None | SSOConfigUpdateMetadataType0 | Unset):
        entity_id (None | str | Unset):
        sso_url (None | str | Unset):
        certificate (None | str | Unset):
    """

    name: None | str | Unset = UNSET
    status: None | SSOStatus | Unset = UNSET
    metadata: None | SSOConfigUpdateMetadataType0 | Unset = UNSET
    entity_id: None | str | Unset = UNSET
    sso_url: None | str | Unset = UNSET
    certificate: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.sso_config_update_metadata_type_0 import SSOConfigUpdateMetadataType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, SSOStatus):
            status = self.status.value
        else:
            status = self.status

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, SSOConfigUpdateMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

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
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
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
        from ..models.sso_config_update_metadata_type_0 import SSOConfigUpdateMetadataType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_status(data: object) -> None | SSOStatus | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = SSOStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSOStatus | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_metadata(data: object) -> None | SSOConfigUpdateMetadataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = SSOConfigUpdateMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SSOConfigUpdateMetadataType0 | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

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

        sso_config_update = cls(
            name=name,
            status=status,
            metadata=metadata,
            entity_id=entity_id,
            sso_url=sso_url,
            certificate=certificate,
        )

        sso_config_update.additional_properties = d
        return sso_config_update

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
