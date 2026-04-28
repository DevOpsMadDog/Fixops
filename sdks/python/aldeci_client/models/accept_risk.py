from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AcceptRisk")


@_attrs_define
class AcceptRisk:
    """
    Attributes:
        accepted_by (str):
        reason (str):
        expiry_date (None | str | Unset):
    """

    accepted_by: str
    reason: str
    expiry_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        accepted_by = self.accepted_by

        reason = self.reason

        expiry_date: None | str | Unset
        if isinstance(self.expiry_date, Unset):
            expiry_date = UNSET
        else:
            expiry_date = self.expiry_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "accepted_by": accepted_by,
                "reason": reason,
            }
        )
        if expiry_date is not UNSET:
            field_dict["expiry_date"] = expiry_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        accepted_by = d.pop("accepted_by")

        reason = d.pop("reason")

        def _parse_expiry_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expiry_date = _parse_expiry_date(d.pop("expiry_date", UNSET))

        accept_risk = cls(
            accepted_by=accepted_by,
            reason=reason,
            expiry_date=expiry_date,
        )

        accept_risk.additional_properties = d
        return accept_risk

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
