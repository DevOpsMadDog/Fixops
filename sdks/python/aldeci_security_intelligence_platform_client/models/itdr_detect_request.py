from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.itdr_detect_request_auth_events_type_0_item import ITDRDetectRequestAuthEventsType0Item
    from ..models.itdr_detect_request_templates_type_0_item import ITDRDetectRequestTemplatesType0Item


T = TypeVar("T", bound="ITDRDetectRequest")


@_attrs_define
class ITDRDetectRequest:
    """
    Attributes:
        org_id (str | Unset): Organization identifier Default: 'default'.
        templates (list[ITDRDetectRequestTemplatesType0Item] | None | Unset): ADCS certificate templates (for ESC1/ESC4)
        auth_events (list[ITDRDetectRequestAuthEventsType0Item] | None | Unset): Kerberos/LSASS auth events (for
            Golden/Skeleton ticket)
    """

    org_id: str | Unset = "default"
    templates: list[ITDRDetectRequestTemplatesType0Item] | None | Unset = UNSET
    auth_events: list[ITDRDetectRequestAuthEventsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        templates: list[dict[str, Any]] | None | Unset
        if isinstance(self.templates, Unset):
            templates = UNSET
        elif isinstance(self.templates, list):
            templates = []
            for templates_type_0_item_data in self.templates:
                templates_type_0_item = templates_type_0_item_data.to_dict()
                templates.append(templates_type_0_item)

        else:
            templates = self.templates

        auth_events: list[dict[str, Any]] | None | Unset
        if isinstance(self.auth_events, Unset):
            auth_events = UNSET
        elif isinstance(self.auth_events, list):
            auth_events = []
            for auth_events_type_0_item_data in self.auth_events:
                auth_events_type_0_item = auth_events_type_0_item_data.to_dict()
                auth_events.append(auth_events_type_0_item)

        else:
            auth_events = self.auth_events

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if templates is not UNSET:
            field_dict["templates"] = templates
        if auth_events is not UNSET:
            field_dict["auth_events"] = auth_events

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.itdr_detect_request_auth_events_type_0_item import ITDRDetectRequestAuthEventsType0Item
        from ..models.itdr_detect_request_templates_type_0_item import ITDRDetectRequestTemplatesType0Item

        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_templates(data: object) -> list[ITDRDetectRequestTemplatesType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                templates_type_0 = []
                _templates_type_0 = data
                for templates_type_0_item_data in _templates_type_0:
                    templates_type_0_item = ITDRDetectRequestTemplatesType0Item.from_dict(templates_type_0_item_data)

                    templates_type_0.append(templates_type_0_item)

                return templates_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ITDRDetectRequestTemplatesType0Item] | None | Unset, data)

        templates = _parse_templates(d.pop("templates", UNSET))

        def _parse_auth_events(data: object) -> list[ITDRDetectRequestAuthEventsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                auth_events_type_0 = []
                _auth_events_type_0 = data
                for auth_events_type_0_item_data in _auth_events_type_0:
                    auth_events_type_0_item = ITDRDetectRequestAuthEventsType0Item.from_dict(
                        auth_events_type_0_item_data
                    )

                    auth_events_type_0.append(auth_events_type_0_item)

                return auth_events_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[ITDRDetectRequestAuthEventsType0Item] | None | Unset, data)

        auth_events = _parse_auth_events(d.pop("auth_events", UNSET))

        itdr_detect_request = cls(
            org_id=org_id,
            templates=templates,
            auth_events=auth_events,
        )

        itdr_detect_request.additional_properties = d
        return itdr_detect_request

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
