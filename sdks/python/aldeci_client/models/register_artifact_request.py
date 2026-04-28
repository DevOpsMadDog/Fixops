from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_artifact_request_metadata import RegisterArtifactRequestMetadata


T = TypeVar("T", bound="RegisterArtifactRequest")


@_attrs_define
class RegisterArtifactRequest:
    """
    Attributes:
        name (str):
        version (str):
        commit_sha (str):
        artifact_type (str | Unset):  Default: 'docker_image'.
        sha256 (None | str | Unset):
        builder (str | Unset):  Default: 'unknown'.
        build_url (None | str | Unset):
        size_bytes (int | Unset):  Default: 0.
        metadata (RegisterArtifactRequestMetadata | Unset):
    """

    name: str
    version: str
    commit_sha: str
    artifact_type: str | Unset = "docker_image"
    sha256: None | str | Unset = UNSET
    builder: str | Unset = "unknown"
    build_url: None | str | Unset = UNSET
    size_bytes: int | Unset = 0
    metadata: RegisterArtifactRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        version = self.version

        commit_sha = self.commit_sha

        artifact_type = self.artifact_type

        sha256: None | str | Unset
        if isinstance(self.sha256, Unset):
            sha256 = UNSET
        else:
            sha256 = self.sha256

        builder = self.builder

        build_url: None | str | Unset
        if isinstance(self.build_url, Unset):
            build_url = UNSET
        else:
            build_url = self.build_url

        size_bytes = self.size_bytes

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "version": version,
                "commit_sha": commit_sha,
            }
        )
        if artifact_type is not UNSET:
            field_dict["artifact_type"] = artifact_type
        if sha256 is not UNSET:
            field_dict["sha256"] = sha256
        if builder is not UNSET:
            field_dict["builder"] = builder
        if build_url is not UNSET:
            field_dict["build_url"] = build_url
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_artifact_request_metadata import RegisterArtifactRequestMetadata

        d = dict(src_dict)
        name = d.pop("name")

        version = d.pop("version")

        commit_sha = d.pop("commit_sha")

        artifact_type = d.pop("artifact_type", UNSET)

        def _parse_sha256(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sha256 = _parse_sha256(d.pop("sha256", UNSET))

        builder = d.pop("builder", UNSET)

        def _parse_build_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        build_url = _parse_build_url(d.pop("build_url", UNSET))

        size_bytes = d.pop("size_bytes", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: RegisterArtifactRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = RegisterArtifactRequestMetadata.from_dict(_metadata)

        register_artifact_request = cls(
            name=name,
            version=version,
            commit_sha=commit_sha,
            artifact_type=artifact_type,
            sha256=sha256,
            builder=builder,
            build_url=build_url,
            size_bytes=size_bytes,
            metadata=metadata,
        )

        register_artifact_request.additional_properties = d
        return register_artifact_request

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
