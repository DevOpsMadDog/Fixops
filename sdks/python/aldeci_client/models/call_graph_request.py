from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CallGraphRequest")


@_attrs_define
class CallGraphRequest:
    """
    Attributes:
        repo (str):
        repo_path (None | str | Unset):
        language (str | Unset):  Default: 'python'.
        entry_points (list[str] | Unset):
    """

    repo: str
    repo_path: None | str | Unset = UNSET
    language: str | Unset = "python"
    entry_points: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo = self.repo

        repo_path: None | str | Unset
        if isinstance(self.repo_path, Unset):
            repo_path = UNSET
        else:
            repo_path = self.repo_path

        language = self.language

        entry_points: list[str] | Unset = UNSET
        if not isinstance(self.entry_points, Unset):
            entry_points = self.entry_points

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo": repo,
            }
        )
        if repo_path is not UNSET:
            field_dict["repo_path"] = repo_path
        if language is not UNSET:
            field_dict["language"] = language
        if entry_points is not UNSET:
            field_dict["entry_points"] = entry_points

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo = d.pop("repo")

        def _parse_repo_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        repo_path = _parse_repo_path(d.pop("repo_path", UNSET))

        language = d.pop("language", UNSET)

        entry_points = cast(list[str], d.pop("entry_points", UNSET))

        call_graph_request = cls(
            repo=repo,
            repo_path=repo_path,
            language=language,
            entry_points=entry_points,
        )

        call_graph_request.additional_properties = d
        return call_graph_request

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
