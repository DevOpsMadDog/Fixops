from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExecuteQueryBody")


@_attrs_define
class ExecuteQueryBody:
    """
    Attributes:
        records_scanned (int | Unset): Number of records scanned Default: 0.
        findings (int | Unset): Number of findings returned Default: 0.
        execution_secs (float | Unset): Execution time in seconds Default: 0.0.
        notes (str | Unset): Optional execution notes Default: ''.
    """

    records_scanned: int | Unset = 0
    findings: int | Unset = 0
    execution_secs: float | Unset = 0.0
    notes: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        records_scanned = self.records_scanned

        findings = self.findings

        execution_secs = self.execution_secs

        notes = self.notes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if records_scanned is not UNSET:
            field_dict["records_scanned"] = records_scanned
        if findings is not UNSET:
            field_dict["findings"] = findings
        if execution_secs is not UNSET:
            field_dict["execution_secs"] = execution_secs
        if notes is not UNSET:
            field_dict["notes"] = notes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        records_scanned = d.pop("records_scanned", UNSET)

        findings = d.pop("findings", UNSET)

        execution_secs = d.pop("execution_secs", UNSET)

        notes = d.pop("notes", UNSET)

        execute_query_body = cls(
            records_scanned=records_scanned,
            findings=findings,
            execution_secs=execution_secs,
            notes=notes,
        )

        execute_query_body.additional_properties = d
        return execute_query_body

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
