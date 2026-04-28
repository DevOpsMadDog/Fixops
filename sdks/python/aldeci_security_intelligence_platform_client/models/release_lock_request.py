from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ReleaseLockRequest")


@_attrs_define
class ReleaseLockRequest:
    """
    Attributes:
        repo_path (str):
        owner_token (None | str | Unset): Token returned from acquire-lock
    """

    repo_path: str
    owner_token: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_path = self.repo_path

        owner_token: None | str | Unset
        if isinstance(self.owner_token, Unset):
            owner_token = UNSET
        else:
            owner_token = self.owner_token

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_path": repo_path,
            }
        )
        if owner_token is not UNSET:
            field_dict["owner_token"] = owner_token

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_path = d.pop("repo_path")

        def _parse_owner_token(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_token = _parse_owner_token(d.pop("owner_token", UNSET))

        release_lock_request = cls(
            repo_path=repo_path,
            owner_token=owner_token,
        )

        release_lock_request.additional_properties = d
        return release_lock_request

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
