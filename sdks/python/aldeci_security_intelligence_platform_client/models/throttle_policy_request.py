from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThrottlePolicyRequest")


@_attrs_define
class ThrottlePolicyRequest:
    """
    Attributes:
        target_id (str): API key ID or IP address to throttle
        burst_limit (int): Max requests in 10-second burst window
        sustained_limit (int): Max requests in 60-second sustained window
        requests_per_minute (int):
        requests_per_hour (int):
        target_type (str | Unset): 'api_key' or 'ip' Default: 'api_key'.
        description (str | Unset):  Default: ''.
    """

    target_id: str
    burst_limit: int
    sustained_limit: int
    requests_per_minute: int
    requests_per_hour: int
    target_type: str | Unset = "api_key"
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_id = self.target_id

        burst_limit = self.burst_limit

        sustained_limit = self.sustained_limit

        requests_per_minute = self.requests_per_minute

        requests_per_hour = self.requests_per_hour

        target_type = self.target_type

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target_id": target_id,
                "burst_limit": burst_limit,
                "sustained_limit": sustained_limit,
                "requests_per_minute": requests_per_minute,
                "requests_per_hour": requests_per_hour,
            }
        )
        if target_type is not UNSET:
            field_dict["target_type"] = target_type
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_id = d.pop("target_id")

        burst_limit = d.pop("burst_limit")

        sustained_limit = d.pop("sustained_limit")

        requests_per_minute = d.pop("requests_per_minute")

        requests_per_hour = d.pop("requests_per_hour")

        target_type = d.pop("target_type", UNSET)

        description = d.pop("description", UNSET)

        throttle_policy_request = cls(
            target_id=target_id,
            burst_limit=burst_limit,
            sustained_limit=sustained_limit,
            requests_per_minute=requests_per_minute,
            requests_per_hour=requests_per_hour,
            target_type=target_type,
            description=description,
        )

        throttle_policy_request.additional_properties = d
        return throttle_policy_request

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
