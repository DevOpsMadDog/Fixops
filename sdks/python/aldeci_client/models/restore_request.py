from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RestoreRequest")


@_attrs_define
class RestoreRequest:
    """
    Attributes:
        target_databases (list[str] | None | Unset):
    """

    target_databases: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_databases: list[str] | None | Unset
        if isinstance(self.target_databases, Unset):
            target_databases = UNSET
        elif isinstance(self.target_databases, list):
            target_databases = self.target_databases

        else:
            target_databases = self.target_databases

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target_databases is not UNSET:
            field_dict["target_databases"] = target_databases

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_target_databases(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                target_databases_type_0 = cast(list[str], data)

                return target_databases_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        target_databases = _parse_target_databases(d.pop("target_databases", UNSET))

        restore_request = cls(
            target_databases=target_databases,
        )

        restore_request.additional_properties = d
        return restore_request

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
