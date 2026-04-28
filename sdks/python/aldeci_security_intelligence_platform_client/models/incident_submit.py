from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.incident_submit_raw_data import IncidentSubmitRawData


T = TypeVar("T", bound="IncidentSubmit")


@_attrs_define
class IncidentSubmit:
    """
    Attributes:
        title (str):
        source (str):
        severity (str | Unset):  Default: 'medium'.
        raw_data (IncidentSubmitRawData | Unset):
    """

    title: str
    source: str
    severity: str | Unset = "medium"
    raw_data: IncidentSubmitRawData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        source = self.source

        severity = self.severity

        raw_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.raw_data, Unset):
            raw_data = self.raw_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "source": source,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if raw_data is not UNSET:
            field_dict["raw_data"] = raw_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.incident_submit_raw_data import IncidentSubmitRawData

        d = dict(src_dict)
        title = d.pop("title")

        source = d.pop("source")

        severity = d.pop("severity", UNSET)

        _raw_data = d.pop("raw_data", UNSET)
        raw_data: IncidentSubmitRawData | Unset
        if isinstance(_raw_data, Unset):
            raw_data = UNSET
        else:
            raw_data = IncidentSubmitRawData.from_dict(_raw_data)

        incident_submit = cls(
            title=title,
            source=source,
            severity=severity,
            raw_data=raw_data,
        )

        incident_submit.additional_properties = d
        return incident_submit

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
