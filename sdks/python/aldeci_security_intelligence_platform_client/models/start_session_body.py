from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StartSessionBody")


@_attrs_define
class StartSessionBody:
    """
    Attributes:
        user (str): User initiating the session
        target_host (str): Target host name or FQDN
        session_type (str | Unset): ssh | rdp | database | api | console | winrm | telnet Default: 'ssh'.
        target_ip (str | Unset): Target IP address Default: ''.
        initiated_by (str | Unset): System or PAM that initiated the session Default: ''.
    """

    user: str
    target_host: str
    session_type: str | Unset = "ssh"
    target_ip: str | Unset = ""
    initiated_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user = self.user

        target_host = self.target_host

        session_type = self.session_type

        target_ip = self.target_ip

        initiated_by = self.initiated_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user": user,
                "target_host": target_host,
            }
        )
        if session_type is not UNSET:
            field_dict["session_type"] = session_type
        if target_ip is not UNSET:
            field_dict["target_ip"] = target_ip
        if initiated_by is not UNSET:
            field_dict["initiated_by"] = initiated_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user = d.pop("user")

        target_host = d.pop("target_host")

        session_type = d.pop("session_type", UNSET)

        target_ip = d.pop("target_ip", UNSET)

        initiated_by = d.pop("initiated_by", UNSET)

        start_session_body = cls(
            user=user,
            target_host=target_host,
            session_type=session_type,
            target_ip=target_ip,
            initiated_by=initiated_by,
        )

        start_session_body.additional_properties = d
        return start_session_body

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
