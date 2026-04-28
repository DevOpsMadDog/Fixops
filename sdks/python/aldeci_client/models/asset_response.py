from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.asset_response_metadata import AssetResponseMetadata


T = TypeVar("T", bound="AssetResponse")


@_attrs_define
class AssetResponse:
    """Response model for generic assets.

    Attributes:
        id (str):
        name (str):
        type_ (str):
        status (str):
        created_at (str):
        updated_at (str):
        criticality (None | str | Unset):
        owner_team (None | str | Unset):
        environment (None | str | Unset):
        metadata (AssetResponseMetadata | Unset):
    """

    id: str
    name: str
    type_: str
    status: str
    created_at: str
    updated_at: str
    criticality: None | str | Unset = UNSET
    owner_team: None | str | Unset = UNSET
    environment: None | str | Unset = UNSET
    metadata: AssetResponseMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        type_ = self.type_

        status = self.status

        created_at = self.created_at

        updated_at = self.updated_at

        criticality: None | str | Unset
        if isinstance(self.criticality, Unset):
            criticality = UNSET
        else:
            criticality = self.criticality

        owner_team: None | str | Unset
        if isinstance(self.owner_team, Unset):
            owner_team = UNSET
        else:
            owner_team = self.owner_team

        environment: None | str | Unset
        if isinstance(self.environment, Unset):
            environment = UNSET
        else:
            environment = self.environment

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "type": type_,
                "status": status,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if environment is not UNSET:
            field_dict["environment"] = environment
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.asset_response_metadata import AssetResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        type_ = d.pop("type")

        status = d.pop("status")

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        def _parse_criticality(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        criticality = _parse_criticality(d.pop("criticality", UNSET))

        def _parse_owner_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_team = _parse_owner_team(d.pop("owner_team", UNSET))

        def _parse_environment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        environment = _parse_environment(d.pop("environment", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: AssetResponseMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AssetResponseMetadata.from_dict(_metadata)

        asset_response = cls(
            id=id,
            name=name,
            type_=type_,
            status=status,
            created_at=created_at,
            updated_at=updated_at,
            criticality=criticality,
            owner_team=owner_team,
            environment=environment,
            metadata=metadata,
        )

        asset_response.additional_properties = d
        return asset_response

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
