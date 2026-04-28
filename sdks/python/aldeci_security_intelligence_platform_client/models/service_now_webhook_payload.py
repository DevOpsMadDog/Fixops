from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.service_now_webhook_payload_additional_info_type_0 import ServiceNowWebhookPayloadAdditionalInfoType0


T = TypeVar("T", bound="ServiceNowWebhookPayload")


@_attrs_define
class ServiceNowWebhookPayload:
    """
    Attributes:
        event_type (str):
        sys_id (str):
        number (None | str | Unset):
        state (None | str | Unset):
        assignment_group (None | str | Unset):
        assigned_to (None | str | Unset):
        short_description (None | str | Unset):
        additional_info (None | ServiceNowWebhookPayloadAdditionalInfoType0 | Unset):
    """

    event_type: str
    sys_id: str
    number: None | str | Unset = UNSET
    state: None | str | Unset = UNSET
    assignment_group: None | str | Unset = UNSET
    assigned_to: None | str | Unset = UNSET
    short_description: None | str | Unset = UNSET
    additional_info: None | ServiceNowWebhookPayloadAdditionalInfoType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.service_now_webhook_payload_additional_info_type_0 import (
            ServiceNowWebhookPayloadAdditionalInfoType0,
        )

        event_type = self.event_type

        sys_id = self.sys_id

        number: None | str | Unset
        if isinstance(self.number, Unset):
            number = UNSET
        else:
            number = self.number

        state: None | str | Unset
        if isinstance(self.state, Unset):
            state = UNSET
        else:
            state = self.state

        assignment_group: None | str | Unset
        if isinstance(self.assignment_group, Unset):
            assignment_group = UNSET
        else:
            assignment_group = self.assignment_group

        assigned_to: None | str | Unset
        if isinstance(self.assigned_to, Unset):
            assigned_to = UNSET
        else:
            assigned_to = self.assigned_to

        short_description: None | str | Unset
        if isinstance(self.short_description, Unset):
            short_description = UNSET
        else:
            short_description = self.short_description

        additional_info: dict[str, Any] | None | Unset
        if isinstance(self.additional_info, Unset):
            additional_info = UNSET
        elif isinstance(self.additional_info, ServiceNowWebhookPayloadAdditionalInfoType0):
            additional_info = self.additional_info.to_dict()
        else:
            additional_info = self.additional_info

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
                "sys_id": sys_id,
            }
        )
        if number is not UNSET:
            field_dict["number"] = number
        if state is not UNSET:
            field_dict["state"] = state
        if assignment_group is not UNSET:
            field_dict["assignment_group"] = assignment_group
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if short_description is not UNSET:
            field_dict["short_description"] = short_description
        if additional_info is not UNSET:
            field_dict["additional_info"] = additional_info

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.service_now_webhook_payload_additional_info_type_0 import (
            ServiceNowWebhookPayloadAdditionalInfoType0,
        )

        d = dict(src_dict)
        event_type = d.pop("event_type")

        sys_id = d.pop("sys_id")

        def _parse_number(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        number = _parse_number(d.pop("number", UNSET))

        def _parse_state(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        state = _parse_state(d.pop("state", UNSET))

        def _parse_assignment_group(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignment_group = _parse_assignment_group(d.pop("assignment_group", UNSET))

        def _parse_assigned_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to", UNSET))

        def _parse_short_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        short_description = _parse_short_description(d.pop("short_description", UNSET))

        def _parse_additional_info(data: object) -> None | ServiceNowWebhookPayloadAdditionalInfoType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                additional_info_type_0 = ServiceNowWebhookPayloadAdditionalInfoType0.from_dict(data)

                return additional_info_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ServiceNowWebhookPayloadAdditionalInfoType0 | Unset, data)

        additional_info = _parse_additional_info(d.pop("additional_info", UNSET))

        service_now_webhook_payload = cls(
            event_type=event_type,
            sys_id=sys_id,
            number=number,
            state=state,
            assignment_group=assignment_group,
            assigned_to=assigned_to,
            short_description=short_description,
            additional_info=additional_info,
        )

        service_now_webhook_payload.additional_properties = d
        return service_now_webhook_payload

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
