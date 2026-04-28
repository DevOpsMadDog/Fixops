from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FixRequest")


@_attrs_define
class FixRequest:
    """Request body for auto-fix endpoint.

    Attributes:
        dry_run (bool | Unset): If true, report what would be fixed without writing to the database. Default: True.
        issue_types (list[str] | None | Unset): Limit fixes to these issue types (orphan, duplicate). None = all
            fixable.
    """

    dry_run: bool | Unset = True
    issue_types: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dry_run = self.dry_run

        issue_types: list[str] | None | Unset
        if isinstance(self.issue_types, Unset):
            issue_types = UNSET
        elif isinstance(self.issue_types, list):
            issue_types = self.issue_types

        else:
            issue_types = self.issue_types

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dry_run is not UNSET:
            field_dict["dry_run"] = dry_run
        if issue_types is not UNSET:
            field_dict["issue_types"] = issue_types

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        dry_run = d.pop("dry_run", UNSET)

        def _parse_issue_types(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                issue_types_type_0 = cast(list[str], data)

                return issue_types_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        issue_types = _parse_issue_types(d.pop("issue_types", UNSET))

        fix_request = cls(
            dry_run=dry_run,
            issue_types=issue_types,
        )

        fix_request.additional_properties = d
        return fix_request

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
