from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="HealthResponse")


@_attrs_define
class HealthResponse:
    """
    Attributes:
        status (str):
        db_path (str):
        apps (int | None | Unset):
        components (int | None | Unset):
        detail (None | str | Unset):
    """

    status: str
    db_path: str
    apps: int | None | Unset = UNSET
    components: int | None | Unset = UNSET
    detail: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        db_path = self.db_path

        apps: int | None | Unset
        if isinstance(self.apps, Unset):
            apps = UNSET
        else:
            apps = self.apps

        components: int | None | Unset
        if isinstance(self.components, Unset):
            components = UNSET
        else:
            components = self.components

        detail: None | str | Unset
        if isinstance(self.detail, Unset):
            detail = UNSET
        else:
            detail = self.detail

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "db_path": db_path,
            }
        )
        if apps is not UNSET:
            field_dict["apps"] = apps
        if components is not UNSET:
            field_dict["components"] = components
        if detail is not UNSET:
            field_dict["detail"] = detail

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        db_path = d.pop("db_path")

        def _parse_apps(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        apps = _parse_apps(d.pop("apps", UNSET))

        def _parse_components(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        components = _parse_components(d.pop("components", UNSET))

        def _parse_detail(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detail = _parse_detail(d.pop("detail", UNSET))

        health_response = cls(
            status=status,
            db_path=db_path,
            apps=apps,
            components=components,
            detail=detail,
        )

        health_response.additional_properties = d
        return health_response

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
