from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CompleteExecutionBody")


@_attrs_define
class CompleteExecutionBody:
    """
    Attributes:
        outcome (str): finding | no_finding | partial_finding | inconclusive
        findings_count (int | Unset): Number of findings discovered Default: 0.
        iocs_discovered (list[str] | None | Unset): IOCs discovered during hunt
        notes (str | Unset): Hunt notes and observations Default: ''.
    """

    outcome: str
    findings_count: int | Unset = 0
    iocs_discovered: list[str] | None | Unset = UNSET
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        outcome = self.outcome

        findings_count = self.findings_count

        iocs_discovered: list[str] | None | Unset
        if isinstance(self.iocs_discovered, Unset):
            iocs_discovered = UNSET
        elif isinstance(self.iocs_discovered, list):
            iocs_discovered = self.iocs_discovered

        else:
            iocs_discovered = self.iocs_discovered

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "outcome": outcome,
            }
        )
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if iocs_discovered is not UNSET:
            field_dict["iocs_discovered"] = iocs_discovered
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        outcome = d.pop("outcome")

        findings_count = d.pop("findings_count", UNSET)

        def _parse_iocs_discovered(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                iocs_discovered_type_0 = cast(list[str], data)

                return iocs_discovered_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        iocs_discovered = _parse_iocs_discovered(d.pop("iocs_discovered", UNSET))

        notes = d.pop("notes", UNSET)

        complete_execution_body = cls(
            outcome=outcome,
            findings_count=findings_count,
            iocs_discovered=iocs_discovered,
            notes=notes,
        )

        complete_execution_body.additional_properties = d
        return complete_execution_body

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
