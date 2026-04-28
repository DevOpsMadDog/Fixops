from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LocalStackScanRequest")


@_attrs_define
class LocalStackScanRequest:
    """
    Attributes:
        endpoint_url (str | Unset): LocalStack endpoint URL Default: 'http://localhost:4566'.
        region (str | Unset): AWS region to scan Default: 'us-east-1'.
        services (list[str] | Unset): AWS services to scan (s3, iam, ec2)
    """

    endpoint_url: str | Unset = "http://localhost:4566"
    region: str | Unset = "us-east-1"
    services: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        endpoint_url = self.endpoint_url

        region = self.region

        services: list[str] | Unset = UNSET
        if not isinstance(self.services, Unset):
            services = self.services

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if endpoint_url is not UNSET:
            field_dict["endpoint_url"] = endpoint_url
        if region is not UNSET:
            field_dict["region"] = region
        if services is not UNSET:
            field_dict["services"] = services

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        endpoint_url = d.pop("endpoint_url", UNSET)

        region = d.pop("region", UNSET)

        services = cast(list[str], d.pop("services", UNSET))

        local_stack_scan_request = cls(
            endpoint_url=endpoint_url,
            region=region,
            services=services,
        )

        local_stack_scan_request.additional_properties = d
        return local_stack_scan_request

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
