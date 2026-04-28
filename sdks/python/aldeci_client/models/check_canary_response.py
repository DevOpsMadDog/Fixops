from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.canary_alert import CanaryAlert


T = TypeVar("T", bound="CheckCanaryResponse")


@_attrs_define
class CheckCanaryResponse:
    """
    Attributes:
        matched (bool):
        message (str):
        alert (CanaryAlert | None | Unset):
    """

    matched: bool
    message: str
    alert: CanaryAlert | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.canary_alert import CanaryAlert

        matched = self.matched

        message = self.message

        alert: dict[str, Any] | None | Unset
        if isinstance(self.alert, Unset):
            alert = UNSET
        elif isinstance(self.alert, CanaryAlert):
            alert = self.alert.to_dict()
        else:
            alert = self.alert

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "matched": matched,
                "message": message,
            }
        )
        if alert is not UNSET:
            field_dict["alert"] = alert

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.canary_alert import CanaryAlert

        d = dict(src_dict)
        matched = d.pop("matched")

        message = d.pop("message")

        def _parse_alert(data: object) -> CanaryAlert | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                alert_type_0 = CanaryAlert.from_dict(data)

                return alert_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(CanaryAlert | None | Unset, data)

        alert = _parse_alert(d.pop("alert", UNSET))

        check_canary_response = cls(
            matched=matched,
            message=message,
            alert=alert,
        )

        check_canary_response.additional_properties = d
        return check_canary_response

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
