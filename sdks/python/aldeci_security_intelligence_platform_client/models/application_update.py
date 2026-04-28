from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.application_criticality import ApplicationCriticality
from ..models.application_status import ApplicationStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.application_update_metadata_type_0 import ApplicationUpdateMetadataType0


T = TypeVar("T", bound="ApplicationUpdate")


@_attrs_define
class ApplicationUpdate:
    """Request model for updating an application.

    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        criticality (ApplicationCriticality | None | Unset):
        status (ApplicationStatus | None | Unset):
        owner_team (None | str | Unset):
        repository_url (None | str | Unset):
        environment (None | str | Unset):
        tags (list[str] | None | Unset):
        metadata (ApplicationUpdateMetadataType0 | None | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    criticality: ApplicationCriticality | None | Unset = UNSET
    status: ApplicationStatus | None | Unset = UNSET
    owner_team: None | str | Unset = UNSET
    repository_url: None | str | Unset = UNSET
    environment: None | str | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    metadata: ApplicationUpdateMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.application_update_metadata_type_0 import ApplicationUpdateMetadataType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        criticality: None | str | Unset
        if isinstance(self.criticality, Unset):
            criticality = UNSET
        elif isinstance(self.criticality, ApplicationCriticality):
            criticality = self.criticality.value
        else:
            criticality = self.criticality

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, ApplicationStatus):
            status = self.status.value
        else:
            status = self.status

        owner_team: None | str | Unset
        if isinstance(self.owner_team, Unset):
            owner_team = UNSET
        else:
            owner_team = self.owner_team

        repository_url: None | str | Unset
        if isinstance(self.repository_url, Unset):
            repository_url = UNSET
        else:
            repository_url = self.repository_url

        environment: None | str | Unset
        if isinstance(self.environment, Unset):
            environment = UNSET
        else:
            environment = self.environment

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, ApplicationUpdateMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if criticality is not UNSET:
            field_dict["criticality"] = criticality
        if status is not UNSET:
            field_dict["status"] = status
        if owner_team is not UNSET:
            field_dict["owner_team"] = owner_team
        if repository_url is not UNSET:
            field_dict["repository_url"] = repository_url
        if environment is not UNSET:
            field_dict["environment"] = environment
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.application_update_metadata_type_0 import ApplicationUpdateMetadataType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_criticality(data: object) -> ApplicationCriticality | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                criticality_type_0 = ApplicationCriticality(data)

                return criticality_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ApplicationCriticality | None | Unset, data)

        criticality = _parse_criticality(d.pop("criticality", UNSET))

        def _parse_status(data: object) -> ApplicationStatus | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = ApplicationStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ApplicationStatus | None | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_owner_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_team = _parse_owner_team(d.pop("owner_team", UNSET))

        def _parse_repository_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        repository_url = _parse_repository_url(d.pop("repository_url", UNSET))

        def _parse_environment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        environment = _parse_environment(d.pop("environment", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_metadata(data: object) -> ApplicationUpdateMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = ApplicationUpdateMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ApplicationUpdateMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        application_update = cls(
            name=name,
            description=description,
            criticality=criticality,
            status=status,
            owner_team=owner_team,
            repository_url=repository_url,
            environment=environment,
            tags=tags,
            metadata=metadata,
        )

        application_update.additional_properties = d
        return application_update

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
