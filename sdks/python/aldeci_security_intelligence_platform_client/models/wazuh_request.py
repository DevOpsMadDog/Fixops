from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WazuhRequest")


@_attrs_define
class WazuhRequest:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        alerts_file (None | str | Unset):
        max_events (int | Unset):  Default: 5.
    """

    org_id: str | Unset = "default"
    alerts_file: None | str | Unset = UNSET
    max_events: int | Unset = 5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        alerts_file: None | str | Unset
        if isinstance(self.alerts_file, Unset):
            alerts_file = UNSET
        else:
            alerts_file = self.alerts_file

        max_events = self.max_events

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if alerts_file is not UNSET:
            field_dict["alerts_file"] = alerts_file
        if max_events is not UNSET:
            field_dict["max_events"] = max_events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_alerts_file(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        alerts_file = _parse_alerts_file(d.pop("alerts_file", UNSET))

        max_events = d.pop("max_events", UNSET)

        wazuh_request = cls(
            org_id=org_id,
            alerts_file=alerts_file,
            max_events=max_events,
        )

        wazuh_request.additional_properties = d
        return wazuh_request

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
