from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScheduleReevalRequest")


@_attrs_define
class ScheduleReevalRequest:
    """
    Attributes:
        org_id (str): Organisation ID
        sbom_id (str): SBOM asset / export ID to re-evaluate
        cron_expr (str | Unset): Cron expression Default: '@daily'.
    """

    org_id: str
    sbom_id: str
    cron_expr: str | Unset = "@daily"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        sbom_id = self.sbom_id

        cron_expr = self.cron_expr

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "sbom_id": sbom_id,
            }
        )
        if cron_expr is not UNSET:
            field_dict["cron_expr"] = cron_expr

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        sbom_id = d.pop("sbom_id")

        cron_expr = d.pop("cron_expr", UNSET)

        schedule_reeval_request = cls(
            org_id=org_id,
            sbom_id=sbom_id,
            cron_expr=cron_expr,
        )

        schedule_reeval_request.additional_properties = d
        return schedule_reeval_request

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
