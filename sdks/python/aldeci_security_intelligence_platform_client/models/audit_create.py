from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AuditCreate")


@_attrs_define
class AuditCreate:
    """
    Attributes:
        name (str):
        audit_type (str):
        scope (str):
        auditor (str):
        planned_date (str):
    """

    name: str
    audit_type: str
    scope: str
    auditor: str
    planned_date: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        audit_type = self.audit_type

        scope = self.scope

        auditor = self.auditor

        planned_date = self.planned_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "audit_type": audit_type,
                "scope": scope,
                "auditor": auditor,
                "planned_date": planned_date,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        audit_type = d.pop("audit_type")

        scope = d.pop("scope")

        auditor = d.pop("auditor")

        planned_date = d.pop("planned_date")

        audit_create = cls(
            name=name,
            audit_type=audit_type,
            scope=scope,
            auditor=auditor,
            planned_date=planned_date,
        )

        audit_create.additional_properties = d
        return audit_create

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
