from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.incident_push_request_alerts_item import IncidentPushRequestAlertsItem


T = TypeVar("T", bound="IncidentPushRequest")


@_attrs_define
class IncidentPushRequest:
    """
    Attributes:
        connection_id (str): Connection ID
        alerts (list[IncidentPushRequestAlertsItem]): List of ALDECI alerts to push
        assignment_group (str | Unset): Default assignment group sys_id Default: ''.
    """

    connection_id: str
    alerts: list[IncidentPushRequestAlertsItem]
    assignment_group: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        connection_id = self.connection_id

        alerts = []
        for alerts_item_data in self.alerts:
            alerts_item = alerts_item_data.to_dict()
            alerts.append(alerts_item)

        assignment_group = self.assignment_group

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "connection_id": connection_id,
                "alerts": alerts,
            }
        )
        if assignment_group is not UNSET:
            field_dict["assignment_group"] = assignment_group

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.incident_push_request_alerts_item import IncidentPushRequestAlertsItem

        d = dict(src_dict)
        connection_id = d.pop("connection_id")

        alerts = []
        _alerts = d.pop("alerts")
        for alerts_item_data in _alerts:
            alerts_item = IncidentPushRequestAlertsItem.from_dict(alerts_item_data)

            alerts.append(alerts_item)

        assignment_group = d.pop("assignment_group", UNSET)

        incident_push_request = cls(
            connection_id=connection_id,
            alerts=alerts,
            assignment_group=assignment_group,
        )

        incident_push_request.additional_properties = d
        return incident_push_request

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
