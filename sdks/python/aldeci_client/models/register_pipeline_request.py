from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterPipelineRequest")


@_attrs_define
class RegisterPipelineRequest:
    """
    Attributes:
        name (str): Human-readable pipeline name
        source_type (str | Unset): siem | edr | ndr | cloud | api | database | file | streaming Default: 'siem'.
        source_endpoint (None | str | Unset): Source URL or connection string
        data_format (str | Unset): json | cef | leef | syslog | csv | parquet | avro Default: 'json'.
        transformation_rules_json (None | str | Unset): JSON string of field mapping / transformation rules
        destination (None | str | Unset): Destination system or topic
    """

    name: str
    source_type: str | Unset = "siem"
    source_endpoint: None | str | Unset = UNSET
    data_format: str | Unset = "json"
    transformation_rules_json: None | str | Unset = UNSET
    destination: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        source_type = self.source_type

        source_endpoint: None | str | Unset
        if isinstance(self.source_endpoint, Unset):
            source_endpoint = UNSET
        else:
            source_endpoint = self.source_endpoint

        data_format = self.data_format

        transformation_rules_json: None | str | Unset
        if isinstance(self.transformation_rules_json, Unset):
            transformation_rules_json = UNSET
        else:
            transformation_rules_json = self.transformation_rules_json

        destination: None | str | Unset
        if isinstance(self.destination, Unset):
            destination = UNSET
        else:
            destination = self.destination

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if source_type is not UNSET:
            field_dict["source_type"] = source_type
        if source_endpoint is not UNSET:
            field_dict["source_endpoint"] = source_endpoint
        if data_format is not UNSET:
            field_dict["data_format"] = data_format
        if transformation_rules_json is not UNSET:
            field_dict["transformation_rules_json"] = transformation_rules_json
        if destination is not UNSET:
            field_dict["destination"] = destination

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        source_type = d.pop("source_type", UNSET)

        def _parse_source_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_endpoint = _parse_source_endpoint(d.pop("source_endpoint", UNSET))

        data_format = d.pop("data_format", UNSET)

        def _parse_transformation_rules_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        transformation_rules_json = _parse_transformation_rules_json(d.pop("transformation_rules_json", UNSET))

        def _parse_destination(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        destination = _parse_destination(d.pop("destination", UNSET))

        register_pipeline_request = cls(
            name=name,
            source_type=source_type,
            source_endpoint=source_endpoint,
            data_format=data_format,
            transformation_rules_json=transformation_rules_json,
            destination=destination,
        )

        register_pipeline_request.additional_properties = d
        return register_pipeline_request

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
