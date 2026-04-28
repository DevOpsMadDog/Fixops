from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProcessEventCreate")


@_attrs_define
class ProcessEventCreate:
    """
    Attributes:
        process_name (str | Unset):  Default: ''.
        process_hash (str | Unset):  Default: ''.
        parent_process (str | Unset):  Default: ''.
        cmdline (str | Unset):  Default: ''.
        user (str | Unset):  Default: ''.
        pid (int | Unset):  Default: 0.
        event_type (str | Unset):  Default: 'create'.
        severity (None | str | Unset):
        mitre_technique (str | Unset):  Default: ''.
    """

    process_name: str | Unset = ""
    process_hash: str | Unset = ""
    parent_process: str | Unset = ""
    cmdline: str | Unset = ""
    user: str | Unset = ""
    pid: int | Unset = 0
    event_type: str | Unset = "create"
    severity: None | str | Unset = UNSET
    mitre_technique: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        process_name = self.process_name

        process_hash = self.process_hash

        parent_process = self.parent_process

        cmdline = self.cmdline

        user = self.user

        pid = self.pid

        event_type = self.event_type

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        mitre_technique = self.mitre_technique

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if process_name is not UNSET:
            field_dict["process_name"] = process_name
        if process_hash is not UNSET:
            field_dict["process_hash"] = process_hash
        if parent_process is not UNSET:
            field_dict["parent_process"] = parent_process
        if cmdline is not UNSET:
            field_dict["cmdline"] = cmdline
        if user is not UNSET:
            field_dict["user"] = user
        if pid is not UNSET:
            field_dict["pid"] = pid
        if event_type is not UNSET:
            field_dict["event_type"] = event_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if mitre_technique is not UNSET:
            field_dict["mitre_technique"] = mitre_technique

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        process_name = d.pop("process_name", UNSET)

        process_hash = d.pop("process_hash", UNSET)

        parent_process = d.pop("parent_process", UNSET)

        cmdline = d.pop("cmdline", UNSET)

        user = d.pop("user", UNSET)

        pid = d.pop("pid", UNSET)

        event_type = d.pop("event_type", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        mitre_technique = d.pop("mitre_technique", UNSET)

        process_event_create = cls(
            process_name=process_name,
            process_hash=process_hash,
            parent_process=parent_process,
            cmdline=cmdline,
            user=user,
            pid=pid,
            event_type=event_type,
            severity=severity,
            mitre_technique=mitre_technique,
        )

        process_event_create.additional_properties = d
        return process_event_create

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
