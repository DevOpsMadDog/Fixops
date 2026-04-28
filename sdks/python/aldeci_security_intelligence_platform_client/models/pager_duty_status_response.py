from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PagerDutyStatusResponse")


@_attrs_define
class PagerDutyStatusResponse:
    """
    Attributes:
        configured (bool):
        message (str):
        from_email (None | str | Unset):
    """

    configured: bool
    message: str
    from_email: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        configured = self.configured

        message = self.message

        from_email: None | str | Unset
        if isinstance(self.from_email, Unset):
            from_email = UNSET
        else:
            from_email = self.from_email

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "configured": configured,
                "message": message,
            }
        )
        if from_email is not UNSET:
            field_dict["from_email"] = from_email

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        configured = d.pop("configured")

        message = d.pop("message")

        def _parse_from_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        from_email = _parse_from_email(d.pop("from_email", UNSET))

        pager_duty_status_response = cls(
            configured=configured,
            message=message,
            from_email=from_email,
        )

        pager_duty_status_response.additional_properties = d
        return pager_duty_status_response

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
