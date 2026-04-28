from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="StatusResponse")


@_attrs_define
class StatusResponse:
    """
    Attributes:
        configured (bool):
        is_mock (bool):
        owner (None | str):
        repo (None | str):
        message (str):
    """

    configured: bool
    is_mock: bool
    owner: None | str
    repo: None | str
    message: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        configured = self.configured

        is_mock = self.is_mock

        owner: None | str
        owner = self.owner

        repo: None | str
        repo = self.repo

        message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "configured": configured,
                "is_mock": is_mock,
                "owner": owner,
                "repo": repo,
                "message": message,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        configured = d.pop("configured")

        is_mock = d.pop("is_mock")

        def _parse_owner(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        owner = _parse_owner(d.pop("owner"))

        def _parse_repo(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        repo = _parse_repo(d.pop("repo"))

        message = d.pop("message")

        status_response = cls(
            configured=configured,
            is_mock=is_mock,
            owner=owner,
            repo=repo,
            message=message,
        )

        status_response.additional_properties = d
        return status_response

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
