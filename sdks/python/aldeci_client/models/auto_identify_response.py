from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AutoIdentifyResponse")


@_attrs_define
class AutoIdentifyResponse:
    """
    Attributes:
        model_id (str):
        new_threat_ids (list[str]):
        count (int):
        message (str | Unset):  Default: 'Auto-identification complete'.
    """

    model_id: str
    new_threat_ids: list[str]
    count: int
    message: str | Unset = "Auto-identification complete"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        model_id = self.model_id

        new_threat_ids = self.new_threat_ids

        count = self.count

        message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "model_id": model_id,
                "new_threat_ids": new_threat_ids,
                "count": count,
            }
        )
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        model_id = d.pop("model_id")

        new_threat_ids = cast(list[str], d.pop("new_threat_ids"))

        count = d.pop("count")

        message = d.pop("message", UNSET)

        auto_identify_response = cls(
            model_id=model_id,
            new_threat_ids=new_threat_ids,
            count=count,
            message=message,
        )

        auto_identify_response.additional_properties = d
        return auto_identify_response

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
