from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SendCommRequest")


@_attrs_define
class SendCommRequest:
    """
    Attributes:
        delivered (int | None | Unset): Number of successful deliveries
        failed (int | None | Unset): Number of failed deliveries
    """

    delivered: int | None | Unset = UNSET
    failed: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        delivered: int | None | Unset
        if isinstance(self.delivered, Unset):
            delivered = UNSET
        else:
            delivered = self.delivered

        failed: int | None | Unset
        if isinstance(self.failed, Unset):
            failed = UNSET
        else:
            failed = self.failed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if delivered is not UNSET:
            field_dict["delivered"] = delivered
        if failed is not UNSET:
            field_dict["failed"] = failed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_delivered(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        delivered = _parse_delivered(d.pop("delivered", UNSET))

        def _parse_failed(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        failed = _parse_failed(d.pop("failed", UNSET))

        send_comm_request = cls(
            delivered=delivered,
            failed=failed,
        )

        send_comm_request.additional_properties = d
        return send_comm_request

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
