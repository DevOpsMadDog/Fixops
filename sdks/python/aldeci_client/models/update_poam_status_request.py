from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.poam_status import POAMStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdatePOAMStatusRequest")


@_attrs_define
class UpdatePOAMStatusRequest:
    """
    Attributes:
        status (POAMStatus):
        risk_accepted (bool | Unset): Set true to mark the risk as formally accepted Default: False.
    """

    status: POAMStatus
    risk_accepted: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status.value

        risk_accepted = self.risk_accepted

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
            }
        )
        if risk_accepted is not UNSET:
            field_dict["risk_accepted"] = risk_accepted

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = POAMStatus(d.pop("status"))

        risk_accepted = d.pop("risk_accepted", UNSET)

        update_poam_status_request = cls(
            status=status,
            risk_accepted=risk_accepted,
        )

        update_poam_status_request.additional_properties = d
        return update_poam_status_request

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
