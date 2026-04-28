from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OpenSessionBody")


@_attrs_define
class OpenSessionBody:
    """
    Attributes:
        account_id (str): Privileged account ID
        session_type (str | Unset): ssh | rdp | database | api | console | jump_host Default: 'ssh'.
        target_system (str | Unset): Target system hostname/IP Default: ''.
    """

    account_id: str
    session_type: str | Unset = "ssh"
    target_system: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        session_type = self.session_type

        target_system = self.target_system

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
            }
        )
        if session_type is not UNSET:
            field_dict["session_type"] = session_type
        if target_system is not UNSET:
            field_dict["target_system"] = target_system

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        account_id = d.pop("account_id")

        session_type = d.pop("session_type", UNSET)

        target_system = d.pop("target_system", UNSET)

        open_session_body = cls(
            account_id=account_id,
            session_type=session_type,
            target_system=target_system,
        )

        open_session_body.additional_properties = d
        return open_session_body

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
