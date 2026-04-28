from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RegisterRepoRequest")


@_attrs_define
class RegisterRepoRequest:
    """Register a developer as owner of a repository.

    Attributes:
        repo_name (str): Repository name (e.g. my-org/my-repo)
        developer_email (str): Developer e-mail address
        org_id (str): Organisation identifier
    """

    repo_name: str
    developer_email: str
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_name = self.repo_name

        developer_email = self.developer_email

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_name": repo_name,
                "developer_email": developer_email,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_name = d.pop("repo_name")

        developer_email = d.pop("developer_email")

        org_id = d.pop("org_id")

        register_repo_request = cls(
            repo_name=repo_name,
            developer_email=developer_email,
            org_id=org_id,
        )

        register_repo_request.additional_properties = d
        return register_repo_request

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
