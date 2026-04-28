from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CustomQueryRequest")


@_attrs_define
class CustomQueryRequest:
    """
    Attributes:
        db_name (str):
        table_name (str):
        where_clause (str | Unset):  Default: ''.
        limit (int | Unset):  Default: 100.
    """

    db_name: str
    table_name: str
    where_clause: str | Unset = ""
    limit: int | Unset = 100
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        db_name = self.db_name

        table_name = self.table_name

        where_clause = self.where_clause

        limit = self.limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "db_name": db_name,
                "table_name": table_name,
            }
        )
        if where_clause is not UNSET:
            field_dict["where_clause"] = where_clause
        if limit is not UNSET:
            field_dict["limit"] = limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        db_name = d.pop("db_name")

        table_name = d.pop("table_name")

        where_clause = d.pop("where_clause", UNSET)

        limit = d.pop("limit", UNSET)

        custom_query_request = cls(
            db_name=db_name,
            table_name=table_name,
            where_clause=where_clause,
            limit=limit,
        )

        custom_query_request.additional_properties = d
        return custom_query_request

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
