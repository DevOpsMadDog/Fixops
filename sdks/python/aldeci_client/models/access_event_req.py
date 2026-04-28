from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.access_event_req_details_type_0 import AccessEventReqDetailsType0


T = TypeVar("T", bound="AccessEventReq")


@_attrs_define
class AccessEventReq:
    """
    Attributes:
        org_id (str):
        device_id (str):
        event_type (str):
        location (None | str | Unset):
        switch_port (None | str | Unset):
        details (AccessEventReqDetailsType0 | None | Unset):
    """

    org_id: str
    device_id: str
    event_type: str
    location: None | str | Unset = UNSET
    switch_port: None | str | Unset = UNSET
    details: AccessEventReqDetailsType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.access_event_req_details_type_0 import AccessEventReqDetailsType0

        org_id = self.org_id

        device_id = self.device_id

        event_type = self.event_type

        location: None | str | Unset
        if isinstance(self.location, Unset):
            location = UNSET
        else:
            location = self.location

        switch_port: None | str | Unset
        if isinstance(self.switch_port, Unset):
            switch_port = UNSET
        else:
            switch_port = self.switch_port

        details: dict[str, Any] | None | Unset
        if isinstance(self.details, Unset):
            details = UNSET
        elif isinstance(self.details, AccessEventReqDetailsType0):
            details = self.details.to_dict()
        else:
            details = self.details

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "device_id": device_id,
                "event_type": event_type,
            }
        )
        if location is not UNSET:
            field_dict["location"] = location
        if switch_port is not UNSET:
            field_dict["switch_port"] = switch_port
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.access_event_req_details_type_0 import AccessEventReqDetailsType0

        d = dict(src_dict)
        org_id = d.pop("org_id")

        device_id = d.pop("device_id")

        event_type = d.pop("event_type")

        def _parse_location(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        location = _parse_location(d.pop("location", UNSET))

        def _parse_switch_port(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        switch_port = _parse_switch_port(d.pop("switch_port", UNSET))

        def _parse_details(data: object) -> AccessEventReqDetailsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                details_type_0 = AccessEventReqDetailsType0.from_dict(data)

                return details_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AccessEventReqDetailsType0 | None | Unset, data)

        details = _parse_details(d.pop("details", UNSET))

        access_event_req = cls(
            org_id=org_id,
            device_id=device_id,
            event_type=event_type,
            location=location,
            switch_port=switch_port,
            details=details,
        )

        access_event_req.additional_properties = d
        return access_event_req

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
