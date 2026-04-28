from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.application_response_metadata import ApplicationResponseMetadata


T = TypeVar("T", bound="ApplicationResponse")


@_attrs_define
class ApplicationResponse:
    """Response model for an application.

    Attributes:
        id (str):
        name (str):
        description (str):
        criticality (str):
        status (str):
        owner_team (None | str):
        repository_url (None | str):
        environment (str):
        tags (list[str]):
        metadata (ApplicationResponseMetadata):
        created_at (str):
        updated_at (str):
    """

    id: str
    name: str
    description: str
    criticality: str
    status: str
    owner_team: None | str
    repository_url: None | str
    environment: str
    tags: list[str]
    metadata: ApplicationResponseMetadata
    created_at: str
    updated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        description = self.description

        criticality = self.criticality

        status = self.status

        owner_team: None | str
        owner_team = self.owner_team

        repository_url: None | str
        repository_url = self.repository_url

        environment = self.environment

        tags = self.tags

        metadata = self.metadata.to_dict()

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "description": description,
                "criticality": criticality,
                "status": status,
                "owner_team": owner_team,
                "repository_url": repository_url,
                "environment": environment,
                "tags": tags,
                "metadata": metadata,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.application_response_metadata import ApplicationResponseMetadata

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        description = d.pop("description")

        criticality = d.pop("criticality")

        status = d.pop("status")

        def _parse_owner_team(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        owner_team = _parse_owner_team(d.pop("owner_team"))

        def _parse_repository_url(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        repository_url = _parse_repository_url(d.pop("repository_url"))

        environment = d.pop("environment")

        tags = cast(list[str], d.pop("tags"))

        metadata = ApplicationResponseMetadata.from_dict(d.pop("metadata"))

        created_at = d.pop("created_at")

        updated_at = d.pop("updated_at")

        application_response = cls(
            id=id,
            name=name,
            description=description,
            criticality=criticality,
            status=status,
            owner_team=owner_team,
            repository_url=repository_url,
            environment=environment,
            tags=tags,
            metadata=metadata,
            created_at=created_at,
            updated_at=updated_at,
        )

        application_response.additional_properties = d
        return application_response

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
