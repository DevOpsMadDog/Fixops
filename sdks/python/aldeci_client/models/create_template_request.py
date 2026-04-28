from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateTemplateRequest")


@_attrs_define
class CreateTemplateRequest:
    """
    Attributes:
        template_name (str): Unique template name (required)
        comm_type (str | Unset): initial_notification | status_update | resolution | post_mortem | stakeholder_brief |
            press_release Default: 'status_update'.
        channel (str | Unset): email | slack | teams | sms | pagerduty | status_page | internal Default: 'email'.
        subject_template (None | str | Unset): Subject line template
        body_template (None | str | Unset): Body template with placeholders
        audience (None | str | Unset): Target audience Default: 'internal'.
    """

    template_name: str
    comm_type: str | Unset = "status_update"
    channel: str | Unset = "email"
    subject_template: None | str | Unset = UNSET
    body_template: None | str | Unset = UNSET
    audience: None | str | Unset = "internal"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        template_name = self.template_name

        comm_type = self.comm_type

        channel = self.channel

        subject_template: None | str | Unset
        if isinstance(self.subject_template, Unset):
            subject_template = UNSET
        else:
            subject_template = self.subject_template

        body_template: None | str | Unset
        if isinstance(self.body_template, Unset):
            body_template = UNSET
        else:
            body_template = self.body_template

        audience: None | str | Unset
        if isinstance(self.audience, Unset):
            audience = UNSET
        else:
            audience = self.audience

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "template_name": template_name,
            }
        )
        if comm_type is not UNSET:
            field_dict["comm_type"] = comm_type
        if channel is not UNSET:
            field_dict["channel"] = channel
        if subject_template is not UNSET:
            field_dict["subject_template"] = subject_template
        if body_template is not UNSET:
            field_dict["body_template"] = body_template
        if audience is not UNSET:
            field_dict["audience"] = audience

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        template_name = d.pop("template_name")

        comm_type = d.pop("comm_type", UNSET)

        channel = d.pop("channel", UNSET)

        def _parse_subject_template(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        subject_template = _parse_subject_template(d.pop("subject_template", UNSET))

        def _parse_body_template(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        body_template = _parse_body_template(d.pop("body_template", UNSET))

        def _parse_audience(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        audience = _parse_audience(d.pop("audience", UNSET))

        create_template_request = cls(
            template_name=template_name,
            comm_type=comm_type,
            channel=channel,
            subject_template=subject_template,
            body_template=body_template,
            audience=audience,
        )

        create_template_request.additional_properties = d
        return create_template_request

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
