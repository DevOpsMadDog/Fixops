from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateMappingRequest")


@_attrs_define
class CreateMappingRequest:
    """
    Attributes:
        cluster_id (str):
        integration_type (str):
        external_id (str):
        external_url (None | str | Unset):
        external_status (None | str | Unset):
    """

    cluster_id: str
    integration_type: str
    external_id: str
    external_url: None | str | Unset = UNSET
    external_status: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cluster_id = self.cluster_id

        integration_type = self.integration_type

        external_id = self.external_id

        external_url: None | str | Unset
        if isinstance(self.external_url, Unset):
            external_url = UNSET
        else:
            external_url = self.external_url

        external_status: None | str | Unset
        if isinstance(self.external_status, Unset):
            external_status = UNSET
        else:
            external_status = self.external_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cluster_id": cluster_id,
                "integration_type": integration_type,
                "external_id": external_id,
            }
        )
        if external_url is not UNSET:
            field_dict["external_url"] = external_url
        if external_status is not UNSET:
            field_dict["external_status"] = external_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cluster_id = d.pop("cluster_id")

        integration_type = d.pop("integration_type")

        external_id = d.pop("external_id")

        def _parse_external_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_url = _parse_external_url(d.pop("external_url", UNSET))

        def _parse_external_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        external_status = _parse_external_status(d.pop("external_status", UNSET))

        create_mapping_request = cls(
            cluster_id=cluster_id,
            integration_type=integration_type,
            external_id=external_id,
            external_url=external_url,
            external_status=external_status,
        )

        create_mapping_request.additional_properties = d
        return create_mapping_request

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
