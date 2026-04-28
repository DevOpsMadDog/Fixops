from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="EPSSScore")


@_attrs_define
class EPSSScore:
    """EPSS score for a single CVE.

    Attributes:
        cve_id (str):
        epss (float): Probability of exploitation in 30 days
        percentile (float): Percentile rank among all CVEs
        model_version (str | Unset):  Default: 'v3'.
        score_date (datetime.datetime | Unset):
        cached (bool | Unset):  Default: False.
    """

    cve_id: str
    epss: float
    percentile: float
    model_version: str | Unset = "v3"
    score_date: datetime.datetime | Unset = UNSET
    cached: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        epss = self.epss

        percentile = self.percentile

        model_version = self.model_version

        score_date: str | Unset = UNSET
        if not isinstance(self.score_date, Unset):
            score_date = self.score_date.isoformat()

        cached = self.cached

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "epss": epss,
                "percentile": percentile,
            }
        )
        if model_version is not UNSET:
            field_dict["model_version"] = model_version
        if score_date is not UNSET:
            field_dict["score_date"] = score_date
        if cached is not UNSET:
            field_dict["cached"] = cached

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        epss = d.pop("epss")

        percentile = d.pop("percentile")

        model_version = d.pop("model_version", UNSET)

        _score_date = d.pop("score_date", UNSET)
        score_date: datetime.datetime | Unset
        if isinstance(_score_date, Unset):
            score_date = UNSET
        else:
            score_date = isoparse(_score_date)

        cached = d.pop("cached", UNSET)

        epss_score = cls(
            cve_id=cve_id,
            epss=epss,
            percentile=percentile,
            model_version=model_version,
            score_date=score_date,
            cached=cached,
        )

        epss_score.additional_properties = d
        return epss_score

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
