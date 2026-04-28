from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="OrmParseRequest")


@_attrs_define
class OrmParseRequest:
    """
    Attributes:
        org_id (str):
        repo_ref (str):
        root_path (str):
        orm_framework (str):
    """

    org_id: str
    repo_ref: str
    root_path: str
    orm_framework: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        repo_ref = self.repo_ref

        root_path = self.root_path

        orm_framework = self.orm_framework

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "repo_ref": repo_ref,
                "root_path": root_path,
                "orm_framework": orm_framework,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        repo_ref = d.pop("repo_ref")

        root_path = d.pop("root_path")

        orm_framework = d.pop("orm_framework")

        orm_parse_request = cls(
            org_id=org_id,
            repo_ref=repo_ref,
            root_path=root_path,
            orm_framework=orm_framework,
        )

        orm_parse_request.additional_properties = d
        return orm_parse_request

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
