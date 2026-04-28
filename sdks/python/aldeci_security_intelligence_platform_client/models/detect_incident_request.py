from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DetectIncidentRequest")


@_attrs_define
class DetectIncidentRequest:
    """
    Attributes:
        org_id (str | Unset):  Default: 'default'.
        data_type (str | Unset):  Default: ''.
        channel (str | Unset):  Default: ''.
        content (str | Unset):  Default: ''.
        user_id (str | Unset):  Default: ''.
        user_email (str | Unset):  Default: ''.
        endpoint_hostname (str | Unset):  Default: ''.
        file_name (str | Unset):  Default: ''.
        destination (str | Unset):  Default: ''.
    """

    org_id: str | Unset = "default"
    data_type: str | Unset = ""
    channel: str | Unset = ""
    content: str | Unset = ""
    user_id: str | Unset = ""
    user_email: str | Unset = ""
    endpoint_hostname: str | Unset = ""
    file_name: str | Unset = ""
    destination: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        data_type = self.data_type

        channel = self.channel

        content = self.content

        user_id = self.user_id

        user_email = self.user_email

        endpoint_hostname = self.endpoint_hostname

        file_name = self.file_name

        destination = self.destination

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if data_type is not UNSET:
            field_dict["data_type"] = data_type
        if channel is not UNSET:
            field_dict["channel"] = channel
        if content is not UNSET:
            field_dict["content"] = content
        if user_id is not UNSET:
            field_dict["user_id"] = user_id
        if user_email is not UNSET:
            field_dict["user_email"] = user_email
        if endpoint_hostname is not UNSET:
            field_dict["endpoint_hostname"] = endpoint_hostname
        if file_name is not UNSET:
            field_dict["file_name"] = file_name
        if destination is not UNSET:
            field_dict["destination"] = destination

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        data_type = d.pop("data_type", UNSET)

        channel = d.pop("channel", UNSET)

        content = d.pop("content", UNSET)

        user_id = d.pop("user_id", UNSET)

        user_email = d.pop("user_email", UNSET)

        endpoint_hostname = d.pop("endpoint_hostname", UNSET)

        file_name = d.pop("file_name", UNSET)

        destination = d.pop("destination", UNSET)

        detect_incident_request = cls(
            org_id=org_id,
            data_type=data_type,
            channel=channel,
            content=content,
            user_id=user_id,
            user_email=user_email,
            endpoint_hostname=endpoint_hostname,
            file_name=file_name,
            destination=destination,
        )

        detect_incident_request.additional_properties = d
        return detect_incident_request

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
