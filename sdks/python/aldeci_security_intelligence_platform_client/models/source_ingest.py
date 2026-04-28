from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.source_ingest_additional_data import SourceIngestAdditionalData


T = TypeVar("T", bound="SourceIngest")


@_attrs_define
class SourceIngest:
    """
    Attributes:
        cve_id (str):
        source_name (str):
        source_severity (str | Unset):  Default: 'medium'.
        cvss_score (float | Unset):  Default: 0.0.
        epss_score (float | Unset):  Default: 0.0.
        kev_listed (int | Unset):  Default: 0.
        title (str | Unset):  Default: ''.
        additional_data (SourceIngestAdditionalData | Unset):
    """

    cve_id: str
    source_name: str
    source_severity: str | Unset = "medium"
    cvss_score: float | Unset = 0.0
    epss_score: float | Unset = 0.0
    kev_listed: int | Unset = 0
    title: str | Unset = ""
    additional_data: SourceIngestAdditionalData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        source_name = self.source_name

        source_severity = self.source_severity

        cvss_score = self.cvss_score

        epss_score = self.epss_score

        kev_listed = self.kev_listed

        title = self.title

        additional_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.additional_data, Unset):
            additional_data = self.additional_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
                "source_name": source_name,
            }
        )
        if source_severity is not UNSET:
            field_dict["source_severity"] = source_severity
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if kev_listed is not UNSET:
            field_dict["kev_listed"] = kev_listed
        if title is not UNSET:
            field_dict["title"] = title
        if additional_data is not UNSET:
            field_dict["additional_data"] = additional_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.source_ingest_additional_data import SourceIngestAdditionalData

        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        source_name = d.pop("source_name")

        source_severity = d.pop("source_severity", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        kev_listed = d.pop("kev_listed", UNSET)

        title = d.pop("title", UNSET)

        _additional_data = d.pop("additional_data", UNSET)
        additional_data: SourceIngestAdditionalData | Unset
        if isinstance(_additional_data, Unset):
            additional_data = UNSET
        else:
            additional_data = SourceIngestAdditionalData.from_dict(_additional_data)

        source_ingest = cls(
            cve_id=cve_id,
            source_name=source_name,
            source_severity=source_severity,
            cvss_score=cvss_score,
            epss_score=epss_score,
            kev_listed=kev_listed,
            title=title,
            additional_data=additional_data,
        )

        source_ingest.additional_properties = d
        return source_ingest

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
