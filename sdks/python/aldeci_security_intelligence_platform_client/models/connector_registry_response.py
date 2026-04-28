from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.connector_metadata import ConnectorMetadata


T = TypeVar("T", bound="ConnectorRegistryResponse")


@_attrs_define
class ConnectorRegistryResponse:
    """Response for GET /api/v1/connectors/registry.

    Attributes:
        connectors (list[ConnectorMetadata]): List of registered connectors
        total_count (int): Total number of connectors
    """

    connectors: list[ConnectorMetadata]
    total_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        connectors = []
        for connectors_item_data in self.connectors:
            connectors_item = connectors_item_data.to_dict()
            connectors.append(connectors_item)

        total_count = self.total_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "connectors": connectors,
                "total_count": total_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connector_metadata import ConnectorMetadata

        d = dict(src_dict)
        connectors = []
        _connectors = d.pop("connectors")
        for connectors_item_data in _connectors:
            connectors_item = ConnectorMetadata.from_dict(connectors_item_data)

            connectors.append(connectors_item)

        total_count = d.pop("total_count")

        connector_registry_response = cls(
            connectors=connectors,
            total_count=total_count,
        )

        connector_registry_response.additional_properties = d
        return connector_registry_response

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
