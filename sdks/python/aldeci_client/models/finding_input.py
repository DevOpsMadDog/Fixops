from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FindingInput")


@_attrs_define
class FindingInput:
    """A single security finding from a scanner.

    Attributes:
        title (str): Finding title or name
        id (None | str | Unset): Finding ID
        description (None | str | Unset): Finding description
        severity (None | str | Unset): Severity: critical, high, medium, low, info Default: 'medium'.
        cwe_id (Any | None | Unset): CWE ID (e.g., 'CWE-89', '89', 89, 'cwe-89')
        cve_ids (list[str] | None | Unset): List of CVE IDs (e.g., ['CVE-2021-44228'])
        cve_id (None | str | Unset): Single CVE ID (alias for cve_ids)
    """

    title: str
    id: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    severity: None | str | Unset = "medium"
    cwe_id: Any | None | Unset = UNSET
    cve_ids: list[str] | None | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        id: None | str | Unset
        if isinstance(self.id, Unset):
            id = UNSET
        else:
            id = self.id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        cwe_id: Any | None | Unset
        if isinstance(self.cwe_id, Unset):
            cwe_id = UNSET
        else:
            cwe_id = self.cwe_id

        cve_ids: list[str] | None | Unset
        if isinstance(self.cve_ids, Unset):
            cve_ids = UNSET
        elif isinstance(self.cve_ids, list):
            cve_ids = self.cve_ids

        else:
            cve_ids = self.cve_ids

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        def _parse_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        id = _parse_id(d.pop("id", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_cwe_id(data: object) -> Any | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(Any | None | Unset, data)

        cwe_id = _parse_cwe_id(d.pop("cwe_id", UNSET))

        def _parse_cve_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                cve_ids_type_0 = cast(list[str], data)

                return cve_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        cve_ids = _parse_cve_ids(d.pop("cve_ids", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        finding_input = cls(
            title=title,
            id=id,
            description=description,
            severity=severity,
            cwe_id=cwe_id,
            cve_ids=cve_ids,
            cve_id=cve_id,
        )

        finding_input.additional_properties = d
        return finding_input

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
