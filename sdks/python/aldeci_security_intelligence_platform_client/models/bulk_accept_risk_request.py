from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkAcceptRiskRequest")


@_attrs_define
class BulkAcceptRiskRequest:
    """Request model for bulk accept risk.

    Attributes:
        ids (list[str]):
        justification (str):
        approved_by (str):
        expiry_days (int | None | Unset):  Default: 90.
    """

    ids: list[str]
    justification: str
    approved_by: str
    expiry_days: int | None | Unset = 90
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ids = self.ids

        justification = self.justification

        approved_by = self.approved_by

        expiry_days: int | None | Unset
        if isinstance(self.expiry_days, Unset):
            expiry_days = UNSET
        else:
            expiry_days = self.expiry_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ids": ids,
                "justification": justification,
                "approved_by": approved_by,
            }
        )
        if expiry_days is not UNSET:
            field_dict["expiry_days"] = expiry_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ids = cast(list[str], d.pop("ids"))

        justification = d.pop("justification")

        approved_by = d.pop("approved_by")

        def _parse_expiry_days(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        expiry_days = _parse_expiry_days(d.pop("expiry_days", UNSET))

        bulk_accept_risk_request = cls(
            ids=ids,
            justification=justification,
            approved_by=approved_by,
            expiry_days=expiry_days,
        )

        bulk_accept_risk_request.additional_properties = d
        return bulk_accept_risk_request

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
