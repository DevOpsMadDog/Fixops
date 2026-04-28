from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.privilege_audit_request_users_item import PrivilegeAuditRequestUsersItem


T = TypeVar("T", bound="PrivilegeAuditRequest")


@_attrs_define
class PrivilegeAuditRequest:
    """Run a privilege audit for a specific database.

    Attributes:
        db_id (str):
        users (list[PrivilegeAuditRequestUsersItem] | Unset):
    """

    db_id: str
    users: list[PrivilegeAuditRequestUsersItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        db_id = self.db_id

        users: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.users, Unset):
            users = []
            for users_item_data in self.users:
                users_item = users_item_data.to_dict()
                users.append(users_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "db_id": db_id,
            }
        )
        if users is not UNSET:
            field_dict["users"] = users

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.privilege_audit_request_users_item import PrivilegeAuditRequestUsersItem

        d = dict(src_dict)
        db_id = d.pop("db_id")

        _users = d.pop("users", UNSET)
        users: list[PrivilegeAuditRequestUsersItem] | Unset = UNSET
        if _users is not UNSET:
            users = []
            for users_item_data in _users:
                users_item = PrivilegeAuditRequestUsersItem.from_dict(users_item_data)

                users.append(users_item)

        privilege_audit_request = cls(
            db_id=db_id,
            users=users,
        )

        privilege_audit_request.additional_properties = d
        return privilege_audit_request

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
