from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DependencyUpdateRequest")


@_attrs_define
class DependencyUpdateRequest:
    """Request to update dependencies.

    Attributes:
        sbom_id (None | str | Unset):
        package_ids (list[str] | Unset):
        update_strategy (str | Unset): patch, minor, major, latest Default: 'minor'.
    """

    sbom_id: None | str | Unset = UNSET
    package_ids: list[str] | Unset = UNSET
    update_strategy: str | Unset = "minor"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sbom_id: None | str | Unset
        if isinstance(self.sbom_id, Unset):
            sbom_id = UNSET
        else:
            sbom_id = self.sbom_id

        package_ids: list[str] | Unset = UNSET
        if not isinstance(self.package_ids, Unset):
            package_ids = self.package_ids

        update_strategy = self.update_strategy

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if sbom_id is not UNSET:
            field_dict["sbom_id"] = sbom_id
        if package_ids is not UNSET:
            field_dict["package_ids"] = package_ids
        if update_strategy is not UNSET:
            field_dict["update_strategy"] = update_strategy

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_sbom_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sbom_id = _parse_sbom_id(d.pop("sbom_id", UNSET))

        package_ids = cast(list[str], d.pop("package_ids", UNSET))

        update_strategy = d.pop("update_strategy", UNSET)

        dependency_update_request = cls(
            sbom_id=sbom_id,
            package_ids=package_ids,
            update_strategy=update_strategy,
        )

        dependency_update_request.additional_properties = d
        return dependency_update_request

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
