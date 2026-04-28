from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.provenance_record import ProvenanceRecord


T = TypeVar("T", bound="ProvenanceQueryResponse")


@_attrs_define
class ProvenanceQueryResponse:
    """Response for a provenance lookup.

    Attributes:
        found (bool):
        component_name (str):
        component_version (None | str):
        provenance (None | ProvenanceRecord):
    """

    found: bool
    component_name: str
    component_version: None | str
    provenance: None | ProvenanceRecord
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.provenance_record import ProvenanceRecord

        found = self.found

        component_name = self.component_name

        component_version: None | str
        component_version = self.component_version

        provenance: dict[str, Any] | None
        if isinstance(self.provenance, ProvenanceRecord):
            provenance = self.provenance.to_dict()
        else:
            provenance = self.provenance

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "found": found,
                "component_name": component_name,
                "component_version": component_version,
                "provenance": provenance,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.provenance_record import ProvenanceRecord

        d = dict(src_dict)
        found = d.pop("found")

        component_name = d.pop("component_name")

        def _parse_component_version(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        component_version = _parse_component_version(d.pop("component_version"))

        def _parse_provenance(data: object) -> None | ProvenanceRecord:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                provenance_type_0 = ProvenanceRecord.from_dict(data)

                return provenance_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ProvenanceRecord, data)

        provenance = _parse_provenance(d.pop("provenance"))

        provenance_query_response = cls(
            found=found,
            component_name=component_name,
            component_version=component_version,
            provenance=provenance,
        )

        provenance_query_response.additional_properties = d
        return provenance_query_response

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
