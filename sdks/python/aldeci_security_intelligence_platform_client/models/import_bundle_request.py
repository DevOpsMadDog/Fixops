from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.import_bundle_request_bundle import ImportBundleRequestBundle


T = TypeVar("T", bound="ImportBundleRequest")


@_attrs_define
class ImportBundleRequest:
    """
    Attributes:
        bundle (ImportBundleRequestBundle):
        source_name (str):
    """

    bundle: ImportBundleRequestBundle
    source_name: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle = self.bundle.to_dict()

        source_name = self.source_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bundle": bundle,
                "source_name": source_name,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.import_bundle_request_bundle import ImportBundleRequestBundle

        d = dict(src_dict)
        bundle = ImportBundleRequestBundle.from_dict(d.pop("bundle"))

        source_name = d.pop("source_name")

        import_bundle_request = cls(
            bundle=bundle,
            source_name=source_name,
        )

        import_bundle_request.additional_properties = d
        return import_bundle_request

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
