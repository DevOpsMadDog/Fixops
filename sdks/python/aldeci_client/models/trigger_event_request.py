from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.playbook_trigger import PlaybookTrigger
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.trigger_event_request_event_data import TriggerEventRequestEventData


T = TypeVar("T", bound="TriggerEventRequest")


@_attrs_define
class TriggerEventRequest:
    """Body for evaluating an incoming security event against playbooks.

    Attributes:
        trigger (PlaybookTrigger): Events that can trigger a SOAR playbook.
        org_id (str | Unset): Organisation ID Default: 'default'.
        event_data (TriggerEventRequestEventData | Unset): Additional event context
    """

    trigger: PlaybookTrigger
    org_id: str | Unset = "default"
    event_data: TriggerEventRequestEventData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        trigger = self.trigger.value

        org_id = self.org_id

        event_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.event_data, Unset):
            event_data = self.event_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "trigger": trigger,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if event_data is not UNSET:
            field_dict["event_data"] = event_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.trigger_event_request_event_data import TriggerEventRequestEventData

        d = dict(src_dict)
        trigger = PlaybookTrigger(d.pop("trigger"))

        org_id = d.pop("org_id", UNSET)

        _event_data = d.pop("event_data", UNSET)
        event_data: TriggerEventRequestEventData | Unset
        if isinstance(_event_data, Unset):
            event_data = UNSET
        else:
            event_data = TriggerEventRequestEventData.from_dict(_event_data)

        trigger_event_request = cls(
            trigger=trigger,
            org_id=org_id,
            event_data=event_data,
        )

        trigger_event_request.additional_properties = d
        return trigger_event_request

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
