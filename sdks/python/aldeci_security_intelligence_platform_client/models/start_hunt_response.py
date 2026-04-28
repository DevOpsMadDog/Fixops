from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.hunt_status import HuntStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="StartHuntResponse")


@_attrs_define
class StartHuntResponse:
    """
    Attributes:
        hunt_id (str):
        hypothesis_name (str):
        status (HuntStatus):
        message (str | Unset):  Default: 'Hunt started'.
    """

    hunt_id: str
    hypothesis_name: str
    status: HuntStatus
    message: str | Unset = "Hunt started"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hunt_id = self.hunt_id

        hypothesis_name = self.hypothesis_name

        status = self.status.value

        message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hunt_id": hunt_id,
                "hypothesis_name": hypothesis_name,
                "status": status,
            }
        )
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hunt_id = d.pop("hunt_id")

        hypothesis_name = d.pop("hypothesis_name")

        status = HuntStatus(d.pop("status"))

        message = d.pop("message", UNSET)

        start_hunt_response = cls(
            hunt_id=hunt_id,
            hypothesis_name=hypothesis_name,
            status=status,
            message=message,
        )

        start_hunt_response.additional_properties = d
        return start_hunt_response

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
