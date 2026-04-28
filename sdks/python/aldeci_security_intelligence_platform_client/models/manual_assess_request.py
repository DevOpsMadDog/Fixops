from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ManualAssessRequest")


@_attrs_define
class ManualAssessRequest:
    """
    Attributes:
        ssl_score (float | None | Unset):
        headers_score (float | None | Unset):
        dns_score (float | None | Unset):
        vulnerability_score (float | None | Unset):
        data_handling_score (float | None | Unset):
        assessor (str | Unset): Who performed the assessment Default: 'analyst'.
        notes (str | Unset): Assessment notes Default: ''.
        validity_days (int | Unset):  Default: 90.
    """

    ssl_score: float | None | Unset = UNSET
    headers_score: float | None | Unset = UNSET
    dns_score: float | None | Unset = UNSET
    vulnerability_score: float | None | Unset = UNSET
    data_handling_score: float | None | Unset = UNSET
    assessor: str | Unset = "analyst"
    notes: str | Unset = ""
    validity_days: int | Unset = 90
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ssl_score: float | None | Unset
        if isinstance(self.ssl_score, Unset):
            ssl_score = UNSET
        else:
            ssl_score = self.ssl_score

        headers_score: float | None | Unset
        if isinstance(self.headers_score, Unset):
            headers_score = UNSET
        else:
            headers_score = self.headers_score

        dns_score: float | None | Unset
        if isinstance(self.dns_score, Unset):
            dns_score = UNSET
        else:
            dns_score = self.dns_score

        vulnerability_score: float | None | Unset
        if isinstance(self.vulnerability_score, Unset):
            vulnerability_score = UNSET
        else:
            vulnerability_score = self.vulnerability_score

        data_handling_score: float | None | Unset
        if isinstance(self.data_handling_score, Unset):
            data_handling_score = UNSET
        else:
            data_handling_score = self.data_handling_score

        assessor = self.assessor

        notes = self.notes

        validity_days = self.validity_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if ssl_score is not UNSET:
            field_dict["ssl_score"] = ssl_score
        if headers_score is not UNSET:
            field_dict["headers_score"] = headers_score
        if dns_score is not UNSET:
            field_dict["dns_score"] = dns_score
        if vulnerability_score is not UNSET:
            field_dict["vulnerability_score"] = vulnerability_score
        if data_handling_score is not UNSET:
            field_dict["data_handling_score"] = data_handling_score
        if assessor is not UNSET:
            field_dict["assessor"] = assessor
        if notes is not UNSET:
            field_dict["notes"] = notes
        if validity_days is not UNSET:
            field_dict["validity_days"] = validity_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_ssl_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        ssl_score = _parse_ssl_score(d.pop("ssl_score", UNSET))

        def _parse_headers_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        headers_score = _parse_headers_score(d.pop("headers_score", UNSET))

        def _parse_dns_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        dns_score = _parse_dns_score(d.pop("dns_score", UNSET))

        def _parse_vulnerability_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        vulnerability_score = _parse_vulnerability_score(d.pop("vulnerability_score", UNSET))

        def _parse_data_handling_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        data_handling_score = _parse_data_handling_score(d.pop("data_handling_score", UNSET))

        assessor = d.pop("assessor", UNSET)

        notes = d.pop("notes", UNSET)

        validity_days = d.pop("validity_days", UNSET)

        manual_assess_request = cls(
            ssl_score=ssl_score,
            headers_score=headers_score,
            dns_score=dns_score,
            vulnerability_score=vulnerability_score,
            data_handling_score=data_handling_score,
            assessor=assessor,
            notes=notes,
            validity_days=validity_days,
        )

        manual_assess_request.additional_properties = d
        return manual_assess_request

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
