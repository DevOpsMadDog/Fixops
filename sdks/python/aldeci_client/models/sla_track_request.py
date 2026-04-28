from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SlaTrackRequest")


@_attrs_define
class SlaTrackRequest:
    """
    Attributes:
        vuln_id (str):
        severity (str | Unset):  Default: 'medium'.
        discovered_at (None | str | Unset):
    """

    vuln_id: str
    severity: str | Unset = "medium"
    discovered_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vuln_id = self.vuln_id

        severity = self.severity

        discovered_at: None | str | Unset
        if isinstance(self.discovered_at, Unset):
            discovered_at = UNSET
        else:
            discovered_at = self.discovered_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vuln_id": vuln_id,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if discovered_at is not UNSET:
            field_dict["discovered_at"] = discovered_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vuln_id = d.pop("vuln_id")

        severity = d.pop("severity", UNSET)

        def _parse_discovered_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        discovered_at = _parse_discovered_at(d.pop("discovered_at", UNSET))

        sla_track_request = cls(
            vuln_id=vuln_id,
            severity=severity,
            discovered_at=discovered_at,
        )

        sla_track_request.additional_properties = d
        return sla_track_request

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
