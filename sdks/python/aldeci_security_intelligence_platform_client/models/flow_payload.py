from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.flow_payload_destination import FlowPayloadDestination
    from ..models.flow_payload_processors_item import FlowPayloadProcessorsItem
    from ..models.flow_payload_source import FlowPayloadSource


T = TypeVar("T", bound="FlowPayload")


@_attrs_define
class FlowPayload:
    """POST /flows/register — register a new data flow.

    Attributes:
        source (FlowPayloadSource):
        destination (FlowPayloadDestination):
        data_categories (list[str]):
        processors (list[FlowPayloadProcessorsItem] | Unset):
    """

    source: FlowPayloadSource
    destination: FlowPayloadDestination
    data_categories: list[str]
    processors: list[FlowPayloadProcessorsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source.to_dict()

        destination = self.destination.to_dict()

        data_categories = self.data_categories

        processors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.processors, Unset):
            processors = []
            for processors_item_data in self.processors:
                processors_item = processors_item_data.to_dict()
                processors.append(processors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source": source,
                "destination": destination,
                "data_categories": data_categories,
            }
        )
        if processors is not UNSET:
            field_dict["processors"] = processors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.flow_payload_destination import FlowPayloadDestination
        from ..models.flow_payload_processors_item import FlowPayloadProcessorsItem
        from ..models.flow_payload_source import FlowPayloadSource

        d = dict(src_dict)
        source = FlowPayloadSource.from_dict(d.pop("source"))

        destination = FlowPayloadDestination.from_dict(d.pop("destination"))

        data_categories = cast(list[str], d.pop("data_categories"))

        _processors = d.pop("processors", UNSET)
        processors: list[FlowPayloadProcessorsItem] | Unset = UNSET
        if _processors is not UNSET:
            processors = []
            for processors_item_data in _processors:
                processors_item = FlowPayloadProcessorsItem.from_dict(processors_item_data)

                processors.append(processors_item)

        flow_payload = cls(
            source=source,
            destination=destination,
            data_categories=data_categories,
            processors=processors,
        )

        flow_payload.additional_properties = d
        return flow_payload

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
