from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.submit_scan_request_dependencies_item import SubmitScanRequestDependenciesItem


T = TypeVar("T", bound="SubmitScanRequest")


@_attrs_define
class SubmitScanRequest:
    """
    Attributes:
        dependencies (list[SubmitScanRequestDependenciesItem] | Unset): List of {name, version, license} dependency
            objects
        direct_count (int | Unset): Number of direct dependencies Default: 0.
        transitive_count (int | Unset): Number of transitive dependencies Default: 0.
    """

    dependencies: list[SubmitScanRequestDependenciesItem] | Unset = UNSET
    direct_count: int | Unset = 0
    transitive_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dependencies: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.dependencies, Unset):
            dependencies = []
            for dependencies_item_data in self.dependencies:
                dependencies_item = dependencies_item_data.to_dict()
                dependencies.append(dependencies_item)

        direct_count = self.direct_count

        transitive_count = self.transitive_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if dependencies is not UNSET:
            field_dict["dependencies"] = dependencies
        if direct_count is not UNSET:
            field_dict["direct_count"] = direct_count
        if transitive_count is not UNSET:
            field_dict["transitive_count"] = transitive_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.submit_scan_request_dependencies_item import SubmitScanRequestDependenciesItem

        d = dict(src_dict)
        _dependencies = d.pop("dependencies", UNSET)
        dependencies: list[SubmitScanRequestDependenciesItem] | Unset = UNSET
        if _dependencies is not UNSET:
            dependencies = []
            for dependencies_item_data in _dependencies:
                dependencies_item = SubmitScanRequestDependenciesItem.from_dict(dependencies_item_data)

                dependencies.append(dependencies_item)

        direct_count = d.pop("direct_count", UNSET)

        transitive_count = d.pop("transitive_count", UNSET)

        submit_scan_request = cls(
            dependencies=dependencies,
            direct_count=direct_count,
            transitive_count=transitive_count,
        )

        submit_scan_request.additional_properties = d
        return submit_scan_request

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
