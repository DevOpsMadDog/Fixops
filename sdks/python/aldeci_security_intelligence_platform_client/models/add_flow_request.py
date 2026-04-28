from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.flow_direction import FlowDirection
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_flow_request_metadata import AddFlowRequestMetadata


T = TypeVar("T", bound="AddFlowRequest")


@_attrs_define
class AddFlowRequest:
    """
    Attributes:
        source_zone (str): Source zone ID
        dest_zone (str): Destination zone ID
        ports (list[int] | Unset): Destination ports
        protocol (str | Unset): Network protocol Default: 'tcp'.
        direction (FlowDirection | None | Unset): Flow direction (auto-detected if omitted)
        metadata (AddFlowRequestMetadata | Unset):
    """

    source_zone: str
    dest_zone: str
    ports: list[int] | Unset = UNSET
    protocol: str | Unset = "tcp"
    direction: FlowDirection | None | Unset = UNSET
    metadata: AddFlowRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_zone = self.source_zone

        dest_zone = self.dest_zone

        ports: list[int] | Unset = UNSET
        if not isinstance(self.ports, Unset):
            ports = self.ports

        protocol = self.protocol

        direction: None | str | Unset
        if isinstance(self.direction, Unset):
            direction = UNSET
        elif isinstance(self.direction, FlowDirection):
            direction = self.direction.value
        else:
            direction = self.direction

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_zone": source_zone,
                "dest_zone": dest_zone,
            }
        )
        if ports is not UNSET:
            field_dict["ports"] = ports
        if protocol is not UNSET:
            field_dict["protocol"] = protocol
        if direction is not UNSET:
            field_dict["direction"] = direction
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_flow_request_metadata import AddFlowRequestMetadata

        d = dict(src_dict)
        source_zone = d.pop("source_zone")

        dest_zone = d.pop("dest_zone")

        ports = cast(list[int], d.pop("ports", UNSET))

        protocol = d.pop("protocol", UNSET)

        def _parse_direction(data: object) -> FlowDirection | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                direction_type_0 = FlowDirection(data)

                return direction_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FlowDirection | None | Unset, data)

        direction = _parse_direction(d.pop("direction", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: AddFlowRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AddFlowRequestMetadata.from_dict(_metadata)

        add_flow_request = cls(
            source_zone=source_zone,
            dest_zone=dest_zone,
            ports=ports,
            protocol=protocol,
            direction=direction,
            metadata=metadata,
        )

        add_flow_request.additional_properties = d
        return add_flow_request

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
