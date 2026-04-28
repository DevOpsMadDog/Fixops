from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="AppSummary")


@_attrs_define
class AppSummary:
    """Lightweight app listing entry.

    Attributes:
        app_id (str):
        name (str):
        org_id (None | str):
        criticality (str):
        data_classification (str):
        compliance (list[str]):
        component_count (int):
        created_at (None | str):
        updated_at (None | str):
    """

    app_id: str
    name: str
    org_id: None | str
    criticality: str
    data_classification: str
    compliance: list[str]
    component_count: int
    created_at: None | str
    updated_at: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        name = self.name

        org_id: None | str
        org_id = self.org_id

        criticality = self.criticality

        data_classification = self.data_classification

        compliance = self.compliance

        component_count = self.component_count

        created_at: None | str
        created_at = self.created_at

        updated_at: None | str
        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
                "name": name,
                "org_id": org_id,
                "criticality": criticality,
                "data_classification": data_classification,
                "compliance": compliance,
                "component_count": component_count,
                "created_at": created_at,
                "updated_at": updated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_id = d.pop("app_id")

        name = d.pop("name")

        def _parse_org_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        org_id = _parse_org_id(d.pop("org_id"))

        criticality = d.pop("criticality")

        data_classification = d.pop("data_classification")

        compliance = cast(list[str], d.pop("compliance"))

        component_count = d.pop("component_count")

        def _parse_created_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        created_at = _parse_created_at(d.pop("created_at"))

        def _parse_updated_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        updated_at = _parse_updated_at(d.pop("updated_at"))

        app_summary = cls(
            app_id=app_id,
            name=name,
            org_id=org_id,
            criticality=criticality,
            data_classification=data_classification,
            compliance=compliance,
            component_count=component_count,
            created_at=created_at,
            updated_at=updated_at,
        )

        app_summary.additional_properties = d
        return app_summary

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
