from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExportThreatIntelRequest")


@_attrs_define
class ExportThreatIntelRequest:
    """Request to export threat intelligence for air-gapped sharing.

    Attributes:
        output_path (str): Absolute output path for the exported bundle
        classification (None | str | Unset): Override classification level for this export
    """

    output_path: str
    classification: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        output_path = self.output_path

        classification: None | str | Unset
        if isinstance(self.classification, Unset):
            classification = UNSET
        else:
            classification = self.classification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "output_path": output_path,
            }
        )
        if classification is not UNSET:
            field_dict["classification"] = classification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        output_path = d.pop("output_path")

        def _parse_classification(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        classification = _parse_classification(d.pop("classification", UNSET))

        export_threat_intel_request = cls(
            output_path=output_path,
            classification=classification,
        )

        export_threat_intel_request.additional_properties = d
        return export_threat_intel_request

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
