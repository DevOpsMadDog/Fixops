from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubmitRequestIn")


@_attrs_define
class SubmitRequestIn:
    """
    Attributes:
        org_id (str):
        requester (str):
        requester_dept (str | Unset):  Default: ''.
        priority (str | Unset):  Default: 'medium'.
        request_details (str | Unset):  Default: ''.
    """

    org_id: str
    requester: str
    requester_dept: str | Unset = ""
    priority: str | Unset = "medium"
    request_details: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        requester = self.requester

        requester_dept = self.requester_dept

        priority = self.priority

        request_details = self.request_details

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "requester": requester,
            }
        )
        if requester_dept is not UNSET:
            field_dict["requester_dept"] = requester_dept
        if priority is not UNSET:
            field_dict["priority"] = priority
        if request_details is not UNSET:
            field_dict["request_details"] = request_details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        requester = d.pop("requester")

        requester_dept = d.pop("requester_dept", UNSET)

        priority = d.pop("priority", UNSET)

        request_details = d.pop("request_details", UNSET)

        submit_request_in = cls(
            org_id=org_id,
            requester=requester,
            requester_dept=requester_dept,
            priority=priority,
            request_details=request_details,
        )

        submit_request_in.additional_properties = d
        return submit_request_in

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
