from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DeploymentCreate")


@_attrs_define
class DeploymentCreate:
    """
    Attributes:
        asset_id (str | Unset):  Default: ''.
        hostname (str | Unset):  Default: ''.
        os_type (str | Unset):  Default: 'linux'.
        status (str | Unset):  Default: 'pending'.
        failure_reason (str | Unset):  Default: ''.
        deployed_at (None | str | Unset):
    """

    asset_id: str | Unset = ""
    hostname: str | Unset = ""
    os_type: str | Unset = "linux"
    status: str | Unset = "pending"
    failure_reason: str | Unset = ""
    deployed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        asset_id = self.asset_id

        hostname = self.hostname

        os_type = self.os_type

        status = self.status

        failure_reason = self.failure_reason

        deployed_at: None | str | Unset
        if isinstance(self.deployed_at, Unset):
            deployed_at = UNSET
        else:
            deployed_at = self.deployed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if hostname is not UNSET:
            field_dict["hostname"] = hostname
        if os_type is not UNSET:
            field_dict["os_type"] = os_type
        if status is not UNSET:
            field_dict["status"] = status
        if failure_reason is not UNSET:
            field_dict["failure_reason"] = failure_reason
        if deployed_at is not UNSET:
            field_dict["deployed_at"] = deployed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        asset_id = d.pop("asset_id", UNSET)

        hostname = d.pop("hostname", UNSET)

        os_type = d.pop("os_type", UNSET)

        status = d.pop("status", UNSET)

        failure_reason = d.pop("failure_reason", UNSET)

        def _parse_deployed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        deployed_at = _parse_deployed_at(d.pop("deployed_at", UNSET))

        deployment_create = cls(
            asset_id=asset_id,
            hostname=hostname,
            os_type=os_type,
            status=status,
            failure_reason=failure_reason,
            deployed_at=deployed_at,
        )

        deployment_create.additional_properties = d
        return deployment_create

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
