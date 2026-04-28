from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TreatmentStatusUpdate")


@_attrs_define
class TreatmentStatusUpdate:
    """
    Attributes:
        new_status (str):
        progress_pct (int | None | Unset):
    """

    new_status: str
    progress_pct: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        new_status = self.new_status

        progress_pct: int | None | Unset
        if isinstance(self.progress_pct, Unset):
            progress_pct = UNSET
        else:
            progress_pct = self.progress_pct

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "new_status": new_status,
            }
        )
        if progress_pct is not UNSET:
            field_dict["progress_pct"] = progress_pct

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_status = d.pop("new_status")

        def _parse_progress_pct(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        progress_pct = _parse_progress_pct(d.pop("progress_pct", UNSET))

        treatment_status_update = cls(
            new_status=new_status,
            progress_pct=progress_pct,
        )

        treatment_status_update.additional_properties = d
        return treatment_status_update

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
