from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="VerdictRequest")


@_attrs_define
class VerdictRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        analyst_id (str): Analyst ID issuing the verdict
        verdict (str): confirmed | disputed | closed
        notes (str | Unset): Optional analyst notes Default: ''.
    """

    org_id: str
    analyst_id: str
    verdict: str
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        analyst_id = self.analyst_id

        verdict = self.verdict

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "analyst_id": analyst_id,
                "verdict": verdict,
            }
        )
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        analyst_id = d.pop("analyst_id")

        verdict = d.pop("verdict")

        notes = d.pop("notes", UNSET)

        verdict_request = cls(
            org_id=org_id,
            analyst_id=analyst_id,
            verdict=verdict,
            notes=notes,
        )

        verdict_request.additional_properties = d
        return verdict_request

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
