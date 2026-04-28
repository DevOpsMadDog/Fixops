from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_dependency_request_metadata import AddDependencyRequestMetadata


T = TypeVar("T", bound="AddDependencyRequest")


@_attrs_define
class AddDependencyRequest:
    """
    Attributes:
        source (str): Source package/component
        target (str): Target package/component
        version (None | str | Unset):
        metadata (AddDependencyRequestMetadata | Unset):
    """

    source: str
    target: str
    version: None | str | Unset = UNSET
    metadata: AddDependencyRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source

        target = self.target

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source": source,
                "target": target,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_dependency_request_metadata import AddDependencyRequestMetadata

        d = dict(src_dict)
        source = d.pop("source")

        target = d.pop("target")

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: AddDependencyRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AddDependencyRequestMetadata.from_dict(_metadata)

        add_dependency_request = cls(
            source=source,
            target=target,
            version=version,
            metadata=metadata,
        )

        add_dependency_request.additional_properties = d
        return add_dependency_request

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
