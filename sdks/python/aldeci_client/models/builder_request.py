from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.builder_filter import BuilderFilter


T = TypeVar("T", bound="BuilderRequest")


@_attrs_define
class BuilderRequest:
    """
    Attributes:
        org_id (str):
        core_id (int):
        filters (list[BuilderFilter] | Unset):
        related_to (None | str | Unset):
        limit (int | Unset):  Default: 20.
    """

    org_id: str
    core_id: int
    filters: list[BuilderFilter] | Unset = UNSET
    related_to: None | str | Unset = UNSET
    limit: int | Unset = 20
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        core_id = self.core_id

        filters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.filters, Unset):
            filters = []
            for filters_item_data in self.filters:
                filters_item = filters_item_data.to_dict()
                filters.append(filters_item)

        related_to: None | str | Unset
        if isinstance(self.related_to, Unset):
            related_to = UNSET
        else:
            related_to = self.related_to

        limit = self.limit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "core_id": core_id,
            }
        )
        if filters is not UNSET:
            field_dict["filters"] = filters
        if related_to is not UNSET:
            field_dict["related_to"] = related_to
        if limit is not UNSET:
            field_dict["limit"] = limit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.builder_filter import BuilderFilter

        d = dict(src_dict)
        org_id = d.pop("org_id")

        core_id = d.pop("core_id")

        _filters = d.pop("filters", UNSET)
        filters: list[BuilderFilter] | Unset = UNSET
        if _filters is not UNSET:
            filters = []
            for filters_item_data in _filters:
                filters_item = BuilderFilter.from_dict(filters_item_data)

                filters.append(filters_item)

        def _parse_related_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        related_to = _parse_related_to(d.pop("related_to", UNSET))

        limit = d.pop("limit", UNSET)

        builder_request = cls(
            org_id=org_id,
            core_id=core_id,
            filters=filters,
            related_to=related_to,
            limit=limit,
        )

        builder_request.additional_properties = d
        return builder_request

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
