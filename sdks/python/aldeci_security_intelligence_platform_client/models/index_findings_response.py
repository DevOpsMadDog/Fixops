from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IndexFindingsResponse")


@_attrs_define
class IndexFindingsResponse:
    """Response after indexing findings.

    Attributes:
        indexed (int):
        entity_ids (list[str]):
        status (str):
        deduplicated (int | Unset):  Default: 0.
        merged (int | Unset):  Default: 0.
        failed (int | Unset):  Default: 0.
        errors (list[str] | Unset):
    """

    indexed: int
    entity_ids: list[str]
    status: str
    deduplicated: int | Unset = 0
    merged: int | Unset = 0
    failed: int | Unset = 0
    errors: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        indexed = self.indexed

        entity_ids = self.entity_ids

        status = self.status

        deduplicated = self.deduplicated

        merged = self.merged

        failed = self.failed

        errors: list[str] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = self.errors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "indexed": indexed,
                "entity_ids": entity_ids,
                "status": status,
            }
        )
        if deduplicated is not UNSET:
            field_dict["deduplicated"] = deduplicated
        if merged is not UNSET:
            field_dict["merged"] = merged
        if failed is not UNSET:
            field_dict["failed"] = failed
        if errors is not UNSET:
            field_dict["errors"] = errors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        indexed = d.pop("indexed")

        entity_ids = cast(list[str], d.pop("entity_ids"))

        status = d.pop("status")

        deduplicated = d.pop("deduplicated", UNSET)

        merged = d.pop("merged", UNSET)

        failed = d.pop("failed", UNSET)

        errors = cast(list[str], d.pop("errors", UNSET))

        index_findings_response = cls(
            indexed=indexed,
            entity_ids=entity_ids,
            status=status,
            deduplicated=deduplicated,
            merged=merged,
            failed=failed,
            errors=errors,
        )

        index_findings_response.additional_properties = d
        return index_findings_response

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
