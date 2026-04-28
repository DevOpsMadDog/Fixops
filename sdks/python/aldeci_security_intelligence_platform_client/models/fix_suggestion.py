from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FixSuggestion")


@_attrs_define
class FixSuggestion:
    """Actionable fix suggestion for a security finding.

    Attributes:
        finding_id (str):
        title (str):
        description (str):
        reference_url (str):
        difficulty (str): One of: easy, medium, hard
        estimated_time_minutes (int):
        code_snippet (None | str | Unset):
        upgrade_command (None | str | Unset):
    """

    finding_id: str
    title: str
    description: str
    reference_url: str
    difficulty: str
    estimated_time_minutes: int
    code_snippet: None | str | Unset = UNSET
    upgrade_command: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        description = self.description

        reference_url = self.reference_url

        difficulty = self.difficulty

        estimated_time_minutes = self.estimated_time_minutes

        code_snippet: None | str | Unset
        if isinstance(self.code_snippet, Unset):
            code_snippet = UNSET
        else:
            code_snippet = self.code_snippet

        upgrade_command: None | str | Unset
        if isinstance(self.upgrade_command, Unset):
            upgrade_command = UNSET
        else:
            upgrade_command = self.upgrade_command

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
                "description": description,
                "reference_url": reference_url,
                "difficulty": difficulty,
                "estimated_time_minutes": estimated_time_minutes,
            }
        )
        if code_snippet is not UNSET:
            field_dict["code_snippet"] = code_snippet
        if upgrade_command is not UNSET:
            field_dict["upgrade_command"] = upgrade_command

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        description = d.pop("description")

        reference_url = d.pop("reference_url")

        difficulty = d.pop("difficulty")

        estimated_time_minutes = d.pop("estimated_time_minutes")

        def _parse_code_snippet(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        code_snippet = _parse_code_snippet(d.pop("code_snippet", UNSET))

        def _parse_upgrade_command(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        upgrade_command = _parse_upgrade_command(d.pop("upgrade_command", UNSET))

        fix_suggestion = cls(
            finding_id=finding_id,
            title=title,
            description=description,
            reference_url=reference_url,
            difficulty=difficulty,
            estimated_time_minutes=estimated_time_minutes,
            code_snippet=code_snippet,
            upgrade_command=upgrade_command,
        )

        fix_suggestion.additional_properties = d
        return fix_suggestion

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
