from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddTargetRequest")


@_attrs_define
class AddTargetRequest:
    """
    Attributes:
        name (str): Human-readable target name
        transport (str): syslog_tcp, syslog_udp, splunk_hec, webhook
        output_format (str | Unset): cef, leef, json Default: 'cef'.
        host (str | Unset): Target host (syslog) Default: 'localhost'.
        port (int | Unset): Target port (syslog) Default: 514.
        url (str | Unset): URL (Splunk HEC / webhook) Default: ''.
        token (str | Unset): Auth token (Splunk HEC / webhook) Default: ''.
        index (str | Unset): Splunk index Default: 'fixops'.
        source (str | Unset): Source identifier Default: 'aldeci-ctem'.
        sourcetype (str | Unset): Sourcetype Default: 'aldeci:security'.
        enabled (bool | Unset):  Default: True.
        event_filters (list[str] | Unset): Event types to forward (empty=all)
    """

    name: str
    transport: str
    output_format: str | Unset = "cef"
    host: str | Unset = "localhost"
    port: int | Unset = 514
    url: str | Unset = ""
    token: str | Unset = ""
    index: str | Unset = "fixops"
    source: str | Unset = "aldeci-ctem"
    sourcetype: str | Unset = "aldeci:security"
    enabled: bool | Unset = True
    event_filters: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        transport = self.transport

        output_format = self.output_format

        host = self.host

        port = self.port

        url = self.url

        token = self.token

        index = self.index

        source = self.source

        sourcetype = self.sourcetype

        enabled = self.enabled

        event_filters: list[str] | Unset = UNSET
        if not isinstance(self.event_filters, Unset):
            event_filters = self.event_filters

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "transport": transport,
            }
        )
        if output_format is not UNSET:
            field_dict["output_format"] = output_format
        if host is not UNSET:
            field_dict["host"] = host
        if port is not UNSET:
            field_dict["port"] = port
        if url is not UNSET:
            field_dict["url"] = url
        if token is not UNSET:
            field_dict["token"] = token
        if index is not UNSET:
            field_dict["index"] = index
        if source is not UNSET:
            field_dict["source"] = source
        if sourcetype is not UNSET:
            field_dict["sourcetype"] = sourcetype
        if enabled is not UNSET:
            field_dict["enabled"] = enabled
        if event_filters is not UNSET:
            field_dict["event_filters"] = event_filters

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        transport = d.pop("transport")

        output_format = d.pop("output_format", UNSET)

        host = d.pop("host", UNSET)

        port = d.pop("port", UNSET)

        url = d.pop("url", UNSET)

        token = d.pop("token", UNSET)

        index = d.pop("index", UNSET)

        source = d.pop("source", UNSET)

        sourcetype = d.pop("sourcetype", UNSET)

        enabled = d.pop("enabled", UNSET)

        event_filters = cast(list[str], d.pop("event_filters", UNSET))

        add_target_request = cls(
            name=name,
            transport=transport,
            output_format=output_format,
            host=host,
            port=port,
            url=url,
            token=token,
            index=index,
            source=source,
            sourcetype=sourcetype,
            enabled=enabled,
            event_filters=event_filters,
        )

        add_target_request.additional_properties = d
        return add_target_request

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
