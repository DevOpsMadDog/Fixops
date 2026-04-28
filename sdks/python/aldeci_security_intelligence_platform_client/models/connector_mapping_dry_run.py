from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.connector_mapping_dry_run_mappings_item import ConnectorMappingDryRunMappingsItem
    from ..models.connector_mapping_dry_run_sample_payload import ConnectorMappingDryRunSamplePayload


T = TypeVar("T", bound="ConnectorMappingDryRun")


@_attrs_define
class ConnectorMappingDryRun:
    """
    Attributes:
        connector_id (str):
        sample_payload (ConnectorMappingDryRunSamplePayload | Unset):
        mappings (list[ConnectorMappingDryRunMappingsItem] | Unset):
    """

    connector_id: str
    sample_payload: ConnectorMappingDryRunSamplePayload | Unset = UNSET
    mappings: list[ConnectorMappingDryRunMappingsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        connector_id = self.connector_id

        sample_payload: dict[str, Any] | Unset = UNSET
        if not isinstance(self.sample_payload, Unset):
            sample_payload = self.sample_payload.to_dict()

        mappings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.mappings, Unset):
            mappings = []
            for mappings_item_data in self.mappings:
                mappings_item = mappings_item_data.to_dict()
                mappings.append(mappings_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "connector_id": connector_id,
            }
        )
        if sample_payload is not UNSET:
            field_dict["sample_payload"] = sample_payload
        if mappings is not UNSET:
            field_dict["mappings"] = mappings

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connector_mapping_dry_run_mappings_item import ConnectorMappingDryRunMappingsItem
        from ..models.connector_mapping_dry_run_sample_payload import ConnectorMappingDryRunSamplePayload

        d = dict(src_dict)
        connector_id = d.pop("connector_id")

        _sample_payload = d.pop("sample_payload", UNSET)
        sample_payload: ConnectorMappingDryRunSamplePayload | Unset
        if isinstance(_sample_payload, Unset):
            sample_payload = UNSET
        else:
            sample_payload = ConnectorMappingDryRunSamplePayload.from_dict(_sample_payload)

        _mappings = d.pop("mappings", UNSET)
        mappings: list[ConnectorMappingDryRunMappingsItem] | Unset = UNSET
        if _mappings is not UNSET:
            mappings = []
            for mappings_item_data in _mappings:
                mappings_item = ConnectorMappingDryRunMappingsItem.from_dict(mappings_item_data)

                mappings.append(mappings_item)

        connector_mapping_dry_run = cls(
            connector_id=connector_id,
            sample_payload=sample_payload,
            mappings=mappings,
        )

        connector_mapping_dry_run.additional_properties = d
        return connector_mapping_dry_run

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
