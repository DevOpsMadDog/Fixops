from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_database_request_metadata_type_0 import AddDatabaseRequestMetadataType0
    from ..models.add_database_request_tags_type_0 import AddDatabaseRequestTagsType0


T = TypeVar("T", bound="AddDatabaseRequest")


@_attrs_define
class AddDatabaseRequest:
    """Register a database in the inventory.

    Attributes:
        name (str):
        db_type (str): postgresql | mysql | mongodb | redis | mssql | oracle | sqlite
        host (str):
        port (int):
        version (str | Unset):  Default: 'unknown'.
        tls_enabled (bool | Unset):  Default: False.
        tls_version (None | str | Unset):
        backup_enabled (bool | Unset):  Default: False.
        backup_last_run (None | str | Unset): ISO datetime of last backup
        backup_encrypted (bool | Unset):  Default: False.
        backup_offsite (bool | Unset):  Default: False.
        public_facing (bool | Unset):  Default: False.
        tags (AddDatabaseRequestTagsType0 | None | Unset):
        metadata (AddDatabaseRequestMetadataType0 | None | Unset):
    """

    name: str
    db_type: str
    host: str
    port: int
    version: str | Unset = "unknown"
    tls_enabled: bool | Unset = False
    tls_version: None | str | Unset = UNSET
    backup_enabled: bool | Unset = False
    backup_last_run: None | str | Unset = UNSET
    backup_encrypted: bool | Unset = False
    backup_offsite: bool | Unset = False
    public_facing: bool | Unset = False
    tags: AddDatabaseRequestTagsType0 | None | Unset = UNSET
    metadata: AddDatabaseRequestMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.add_database_request_metadata_type_0 import AddDatabaseRequestMetadataType0
        from ..models.add_database_request_tags_type_0 import AddDatabaseRequestTagsType0

        name = self.name

        db_type = self.db_type

        host = self.host

        port = self.port

        version = self.version

        tls_enabled = self.tls_enabled

        tls_version: None | str | Unset
        if isinstance(self.tls_version, Unset):
            tls_version = UNSET
        else:
            tls_version = self.tls_version

        backup_enabled = self.backup_enabled

        backup_last_run: None | str | Unset
        if isinstance(self.backup_last_run, Unset):
            backup_last_run = UNSET
        else:
            backup_last_run = self.backup_last_run

        backup_encrypted = self.backup_encrypted

        backup_offsite = self.backup_offsite

        public_facing = self.public_facing

        tags: dict[str, Any] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, AddDatabaseRequestTagsType0):
            tags = self.tags.to_dict()
        else:
            tags = self.tags

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, AddDatabaseRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "db_type": db_type,
                "host": host,
                "port": port,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if tls_enabled is not UNSET:
            field_dict["tls_enabled"] = tls_enabled
        if tls_version is not UNSET:
            field_dict["tls_version"] = tls_version
        if backup_enabled is not UNSET:
            field_dict["backup_enabled"] = backup_enabled
        if backup_last_run is not UNSET:
            field_dict["backup_last_run"] = backup_last_run
        if backup_encrypted is not UNSET:
            field_dict["backup_encrypted"] = backup_encrypted
        if backup_offsite is not UNSET:
            field_dict["backup_offsite"] = backup_offsite
        if public_facing is not UNSET:
            field_dict["public_facing"] = public_facing
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_database_request_metadata_type_0 import AddDatabaseRequestMetadataType0
        from ..models.add_database_request_tags_type_0 import AddDatabaseRequestTagsType0

        d = dict(src_dict)
        name = d.pop("name")

        db_type = d.pop("db_type")

        host = d.pop("host")

        port = d.pop("port")

        version = d.pop("version", UNSET)

        tls_enabled = d.pop("tls_enabled", UNSET)

        def _parse_tls_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tls_version = _parse_tls_version(d.pop("tls_version", UNSET))

        backup_enabled = d.pop("backup_enabled", UNSET)

        def _parse_backup_last_run(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        backup_last_run = _parse_backup_last_run(d.pop("backup_last_run", UNSET))

        backup_encrypted = d.pop("backup_encrypted", UNSET)

        backup_offsite = d.pop("backup_offsite", UNSET)

        public_facing = d.pop("public_facing", UNSET)

        def _parse_tags(data: object) -> AddDatabaseRequestTagsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                tags_type_0 = AddDatabaseRequestTagsType0.from_dict(data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AddDatabaseRequestTagsType0 | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_metadata(data: object) -> AddDatabaseRequestMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = AddDatabaseRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AddDatabaseRequestMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        add_database_request = cls(
            name=name,
            db_type=db_type,
            host=host,
            port=port,
            version=version,
            tls_enabled=tls_enabled,
            tls_version=tls_version,
            backup_enabled=backup_enabled,
            backup_last_run=backup_last_run,
            backup_encrypted=backup_encrypted,
            backup_offsite=backup_offsite,
            public_facing=public_facing,
            tags=tags,
            metadata=metadata,
        )

        add_database_request.additional_properties = d
        return add_database_request

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
