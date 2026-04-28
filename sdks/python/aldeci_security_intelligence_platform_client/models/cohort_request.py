from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CohortRequest")


@_attrs_define
class CohortRequest:
    """
    Attributes:
        cohort_name (str):
        vuln_ids (list[str] | Unset):
        avg_age_days (float | Unset):  Default: 0.0.
        avg_cvss (float | Unset):  Default: 0.0.
    """

    cohort_name: str
    vuln_ids: list[str] | Unset = UNSET
    avg_age_days: float | Unset = 0.0
    avg_cvss: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cohort_name = self.cohort_name

        vuln_ids: list[str] | Unset = UNSET
        if not isinstance(self.vuln_ids, Unset):
            vuln_ids = self.vuln_ids

        avg_age_days = self.avg_age_days

        avg_cvss = self.avg_cvss

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cohort_name": cohort_name,
            }
        )
        if vuln_ids is not UNSET:
            field_dict["vuln_ids"] = vuln_ids
        if avg_age_days is not UNSET:
            field_dict["avg_age_days"] = avg_age_days
        if avg_cvss is not UNSET:
            field_dict["avg_cvss"] = avg_cvss

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cohort_name = d.pop("cohort_name")

        vuln_ids = cast(list[str], d.pop("vuln_ids", UNSET))

        avg_age_days = d.pop("avg_age_days", UNSET)

        avg_cvss = d.pop("avg_cvss", UNSET)

        cohort_request = cls(
            cohort_name=cohort_name,
            vuln_ids=vuln_ids,
            avg_age_days=avg_age_days,
            avg_cvss=avg_cvss,
        )

        cohort_request.additional_properties = d
        return cohort_request

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
