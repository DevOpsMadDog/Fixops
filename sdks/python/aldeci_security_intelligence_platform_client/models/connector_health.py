from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.connector_status import ConnectorStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.connector_health_details import ConnectorHealthDetails


T = TypeVar("T", bound="ConnectorHealth")


@_attrs_define
class ConnectorHealth:
    """Health status for a specific connector.

    Attributes:
        name (str): Connector name
        status (ConnectorStatus): Connector health status.
        timestamp (datetime.datetime): Status check timestamp
        details (ConnectorHealthDetails | Unset): Status details
        last_error (None | str | Unset): Last error message (if unhealthy)
    """

    name: str
    status: ConnectorStatus
    timestamp: datetime.datetime
    details: ConnectorHealthDetails | Unset = UNSET
    last_error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        status = self.status.value

        timestamp = self.timestamp.isoformat()

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        last_error: None | str | Unset
        if isinstance(self.last_error, Unset):
            last_error = UNSET
        else:
            last_error = self.last_error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "status": status,
                "timestamp": timestamp,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details
        if last_error is not UNSET:
            field_dict["last_error"] = last_error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connector_health_details import ConnectorHealthDetails

        d = dict(src_dict)
        name = d.pop("name")

        status = ConnectorStatus(d.pop("status"))

        timestamp = isoparse(d.pop("timestamp"))

        _details = d.pop("details", UNSET)
        details: ConnectorHealthDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = ConnectorHealthDetails.from_dict(_details)

        def _parse_last_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_error = _parse_last_error(d.pop("last_error", UNSET))

        connector_health = cls(
            name=name,
            status=status,
            timestamp=timestamp,
            details=details,
            last_error=last_error,
        )

        connector_health.additional_properties = d
        return connector_health

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
