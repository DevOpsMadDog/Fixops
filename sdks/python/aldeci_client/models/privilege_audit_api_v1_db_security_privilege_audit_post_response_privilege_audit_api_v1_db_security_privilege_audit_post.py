from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar(
    "T", bound="PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost"
)


@_attrs_define
class PrivilegeAuditApiV1DbSecurityPrivilegeAuditPostResponsePrivilegeAuditApiV1DbSecurityPrivilegeAuditPost:
    """ """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        privilege_audit_api_v1_db_security_privilege_audit_post_response_privilege_audit_api_v1_db_security_privilege_audit_post = cls()

        privilege_audit_api_v1_db_security_privilege_audit_post_response_privilege_audit_api_v1_db_security_privilege_audit_post.additional_properties = d
        return privilege_audit_api_v1_db_security_privilege_audit_post_response_privilege_audit_api_v1_db_security_privilege_audit_post

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
