from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PublishVersionRequest")


@_attrs_define
class PublishVersionRequest:
    """
    Attributes:
        published_by (str | Unset):  Default: 'api'.
        changelog (str | Unset):  Default: ''.
    """

    published_by: str | Unset = "api"
    changelog: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        published_by = self.published_by

        changelog = self.changelog

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if published_by is not UNSET:
            field_dict["published_by"] = published_by
        if changelog is not UNSET:
            field_dict["changelog"] = changelog

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        published_by = d.pop("published_by", UNSET)

        changelog = d.pop("changelog", UNSET)

        publish_version_request = cls(
            published_by=published_by,
            changelog=changelog,
        )

        publish_version_request.additional_properties = d
        return publish_version_request

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
