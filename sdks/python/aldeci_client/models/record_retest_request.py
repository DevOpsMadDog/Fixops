from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordRetestRequest")


@_attrs_define
class RecordRetestRequest:
    """
    Attributes:
        retested_by (str | Unset):  Default: ''.
        result (str | Unset):  Default: 'not_remediated'.
        notes (str | Unset):  Default: ''.
        retested_at (None | str | Unset):
    """

    retested_by: str | Unset = ""
    result: str | Unset = "not_remediated"
    notes: str | Unset = ""
    retested_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        retested_by = self.retested_by

        result = self.result

        notes = self.notes

        retested_at: None | str | Unset
        if isinstance(self.retested_at, Unset):
            retested_at = UNSET
        else:
            retested_at = self.retested_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if retested_by is not UNSET:
            field_dict["retested_by"] = retested_by
        if result is not UNSET:
            field_dict["result"] = result
        if notes is not UNSET:
            field_dict["notes"] = notes
        if retested_at is not UNSET:
            field_dict["retested_at"] = retested_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        retested_by = d.pop("retested_by", UNSET)

        result = d.pop("result", UNSET)

        notes = d.pop("notes", UNSET)

        def _parse_retested_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        retested_at = _parse_retested_at(d.pop("retested_at", UNSET))

        record_retest_request = cls(
            retested_by=retested_by,
            result=result,
            notes=notes,
            retested_at=retested_at,
        )

        record_retest_request.additional_properties = d
        return record_retest_request

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
