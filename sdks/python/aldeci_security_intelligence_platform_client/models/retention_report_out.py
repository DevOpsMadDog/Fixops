from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RetentionReportOut")


@_attrs_define
class RetentionReportOut:
    """
    Attributes:
        org_id (str):
        archived (int):
        deleted (int):
        held (int):
        skipped (int):
        run_at (str):
    """

    org_id: str
    archived: int
    deleted: int
    held: int
    skipped: int
    run_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        archived = self.archived

        deleted = self.deleted

        held = self.held

        skipped = self.skipped

        run_at = self.run_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "archived": archived,
                "deleted": deleted,
                "held": held,
                "skipped": skipped,
                "run_at": run_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        archived = d.pop("archived")

        deleted = d.pop("deleted")

        held = d.pop("held")

        skipped = d.pop("skipped")

        run_at = d.pop("run_at")

        retention_report_out = cls(
            org_id=org_id,
            archived=archived,
            deleted=deleted,
            held=held,
            skipped=skipped,
            run_at=run_at,
        )

        retention_report_out.additional_properties = d
        return retention_report_out

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
