from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ImportThreatIntelRequest")


@_attrs_define
class ImportThreatIntelRequest:
    """Request to import a STIX/TAXII threat intelligence bundle.

    Attributes:
        bundle_path (str): Absolute path on the server to the STIX/TAXII bundle file
    """

    bundle_path: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle_path = self.bundle_path

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bundle_path": bundle_path,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bundle_path = d.pop("bundle_path")

        import_threat_intel_request = cls(
            bundle_path=bundle_path,
        )

        import_threat_intel_request.additional_properties = d
        return import_threat_intel_request

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
