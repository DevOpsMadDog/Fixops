from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ImportMitreModel")


@_attrs_define
class ImportMitreModel:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        limit (int | None | Unset): Cap number of actors imported (None = all ~150 MITRE groups)
        cached_path (None | str | Unset): Optional local path to cached enterprise-attack.json (skips network fetch)
    """

    org_id: str | Unset = "default"
    limit: int | None | Unset = UNSET
    cached_path: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        limit: int | None | Unset
        if isinstance(self.limit, Unset):
            limit = UNSET
        else:
            limit = self.limit

        cached_path: None | str | Unset
        if isinstance(self.cached_path, Unset):
            cached_path = UNSET
        else:
            cached_path = self.cached_path

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if limit is not UNSET:
            field_dict["limit"] = limit
        if cached_path is not UNSET:
            field_dict["cached_path"] = cached_path

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_limit(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        limit = _parse_limit(d.pop("limit", UNSET))

        def _parse_cached_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cached_path = _parse_cached_path(d.pop("cached_path", UNSET))

        import_mitre_model = cls(
            org_id=org_id,
            limit=limit,
            cached_path=cached_path,
        )

        import_mitre_model.additional_properties = d
        return import_mitre_model

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
