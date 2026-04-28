from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RuntimeMapToCodeRequest")


@_attrs_define
class RuntimeMapToCodeRequest:
    """
    Attributes:
        runtime_event_id (None | str | Unset):
        service_name (None | str | Unset):
        api_path (None | str | Unset):
        stack_trace (None | str | Unset):
        org_id (None | str | Unset):
    """

    runtime_event_id: None | str | Unset = UNSET
    service_name: None | str | Unset = UNSET
    api_path: None | str | Unset = UNSET
    stack_trace: None | str | Unset = UNSET
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        runtime_event_id: None | str | Unset
        if isinstance(self.runtime_event_id, Unset):
            runtime_event_id = UNSET
        else:
            runtime_event_id = self.runtime_event_id

        service_name: None | str | Unset
        if isinstance(self.service_name, Unset):
            service_name = UNSET
        else:
            service_name = self.service_name

        api_path: None | str | Unset
        if isinstance(self.api_path, Unset):
            api_path = UNSET
        else:
            api_path = self.api_path

        stack_trace: None | str | Unset
        if isinstance(self.stack_trace, Unset):
            stack_trace = UNSET
        else:
            stack_trace = self.stack_trace

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if runtime_event_id is not UNSET:
            field_dict["runtime_event_id"] = runtime_event_id
        if service_name is not UNSET:
            field_dict["service_name"] = service_name
        if api_path is not UNSET:
            field_dict["api_path"] = api_path
        if stack_trace is not UNSET:
            field_dict["stack_trace"] = stack_trace
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_runtime_event_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        runtime_event_id = _parse_runtime_event_id(d.pop("runtime_event_id", UNSET))

        def _parse_service_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        service_name = _parse_service_name(d.pop("service_name", UNSET))

        def _parse_api_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_path = _parse_api_path(d.pop("api_path", UNSET))

        def _parse_stack_trace(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stack_trace = _parse_stack_trace(d.pop("stack_trace", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        runtime_map_to_code_request = cls(
            runtime_event_id=runtime_event_id,
            service_name=service_name,
            api_path=api_path,
            stack_trace=stack_trace,
            org_id=org_id,
        )

        runtime_map_to_code_request.additional_properties = d
        return runtime_map_to_code_request

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
