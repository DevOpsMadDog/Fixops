from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dismiss_response_details_type_0 import DismissResponseDetailsType0


T = TypeVar("T", bound="DismissResponse")


@_attrs_define
class DismissResponse:
    """
    Attributes:
        status (str):
        alert_type (str):
        alert_number (int):
        details (DismissResponseDetailsType0 | None | Unset):
        reason (None | str | Unset):
    """

    status: str
    alert_type: str
    alert_number: int
    details: DismissResponseDetailsType0 | None | Unset = UNSET
    reason: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.dismiss_response_details_type_0 import DismissResponseDetailsType0

        status = self.status

        alert_type = self.alert_type

        alert_number = self.alert_number

        details: dict[str, Any] | None | Unset
        if isinstance(self.details, Unset):
            details = UNSET
        elif isinstance(self.details, DismissResponseDetailsType0):
            details = self.details.to_dict()
        else:
            details = self.details

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "alert_type": alert_type,
                "alert_number": alert_number,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dismiss_response_details_type_0 import DismissResponseDetailsType0

        d = dict(src_dict)
        status = d.pop("status")

        alert_type = d.pop("alert_type")

        alert_number = d.pop("alert_number")

        def _parse_details(data: object) -> DismissResponseDetailsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                details_type_0 = DismissResponseDetailsType0.from_dict(data)

                return details_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DismissResponseDetailsType0 | None | Unset, data)

        details = _parse_details(d.pop("details", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        dismiss_response = cls(
            status=status,
            alert_type=alert_type,
            alert_number=alert_number,
            details=details,
            reason=reason,
        )

        dismiss_response.additional_properties = d
        return dismiss_response

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
