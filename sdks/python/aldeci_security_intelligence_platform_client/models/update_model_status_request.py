from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateModelStatusRequest")


@_attrs_define
class UpdateModelStatusRequest:
    """
    Attributes:
        status (str): training | active | deprecated | failed
        last_retrained (None | str | Unset):
    """

    status: str
    last_retrained: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        last_retrained: None | str | Unset
        if isinstance(self.last_retrained, Unset):
            last_retrained = UNSET
        else:
            last_retrained = self.last_retrained

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
            }
        )
        if last_retrained is not UNSET:
            field_dict["last_retrained"] = last_retrained

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        status = d.pop("status")

        def _parse_last_retrained(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_retrained = _parse_last_retrained(d.pop("last_retrained", UNSET))

        update_model_status_request = cls(
            status=status,
            last_retrained=last_retrained,
        )

        update_model_status_request.additional_properties = d
        return update_model_status_request

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
