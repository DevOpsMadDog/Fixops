from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="Suggestion")


@_attrs_define
class Suggestion:
    """Code improvement suggestion.

    Attributes:
        type_ (str):
        message (str):
        line (int):
        priority (str):
        auto_fixable (bool | Unset):  Default: False.
        fix_code (None | str | Unset):
    """

    type_: str
    message: str
    line: int
    priority: str
    auto_fixable: bool | Unset = False
    fix_code: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_

        message = self.message

        line = self.line

        priority = self.priority

        auto_fixable = self.auto_fixable

        fix_code: None | str | Unset
        if isinstance(self.fix_code, Unset):
            fix_code = UNSET
        else:
            fix_code = self.fix_code

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "message": message,
                "line": line,
                "priority": priority,
            }
        )
        if auto_fixable is not UNSET:
            field_dict["auto_fixable"] = auto_fixable
        if fix_code is not UNSET:
            field_dict["fix_code"] = fix_code

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = d.pop("type")

        message = d.pop("message")

        line = d.pop("line")

        priority = d.pop("priority")

        auto_fixable = d.pop("auto_fixable", UNSET)

        def _parse_fix_code(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fix_code = _parse_fix_code(d.pop("fix_code", UNSET))

        suggestion = cls(
            type_=type_,
            message=message,
            line=line,
            priority=priority,
            auto_fixable=auto_fixable,
            fix_code=fix_code,
        )

        suggestion.additional_properties = d
        return suggestion

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
