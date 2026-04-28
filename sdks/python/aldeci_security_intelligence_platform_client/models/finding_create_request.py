from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FindingCreateRequest")


@_attrs_define
class FindingCreateRequest:
    """
    Attributes:
        app_id (str):
        scan_id (None | str | Unset):
        vuln_type (str | Unset):  Default: 'misconfig'.
        severity (str | Unset):  Default: 'medium'.
        cwe_id (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        file_path (str | Unset):  Default: ''.
        line_number (int | Unset):  Default: 0.
        status (str | Unset):  Default: 'open'.
        owasp_category (None | str | Unset):
    """

    app_id: str
    scan_id: None | str | Unset = UNSET
    vuln_type: str | Unset = "misconfig"
    severity: str | Unset = "medium"
    cwe_id: str | Unset = ""
    description: str | Unset = ""
    file_path: str | Unset = ""
    line_number: int | Unset = 0
    status: str | Unset = "open"
    owasp_category: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        scan_id: None | str | Unset
        if isinstance(self.scan_id, Unset):
            scan_id = UNSET
        else:
            scan_id = self.scan_id

        vuln_type = self.vuln_type

        severity = self.severity

        cwe_id = self.cwe_id

        description = self.description

        file_path = self.file_path

        line_number = self.line_number

        status = self.status

        owasp_category: None | str | Unset
        if isinstance(self.owasp_category, Unset):
            owasp_category = UNSET
        else:
            owasp_category = self.owasp_category

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
            }
        )
        if scan_id is not UNSET:
            field_dict["scan_id"] = scan_id
        if vuln_type is not UNSET:
            field_dict["vuln_type"] = vuln_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if description is not UNSET:
            field_dict["description"] = description
        if file_path is not UNSET:
            field_dict["file_path"] = file_path
        if line_number is not UNSET:
            field_dict["line_number"] = line_number
        if status is not UNSET:
            field_dict["status"] = status
        if owasp_category is not UNSET:
            field_dict["owasp_category"] = owasp_category

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_id = d.pop("app_id")

        def _parse_scan_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_id = _parse_scan_id(d.pop("scan_id", UNSET))

        vuln_type = d.pop("vuln_type", UNSET)

        severity = d.pop("severity", UNSET)

        cwe_id = d.pop("cwe_id", UNSET)

        description = d.pop("description", UNSET)

        file_path = d.pop("file_path", UNSET)

        line_number = d.pop("line_number", UNSET)

        status = d.pop("status", UNSET)

        def _parse_owasp_category(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owasp_category = _parse_owasp_category(d.pop("owasp_category", UNSET))

        finding_create_request = cls(
            app_id=app_id,
            scan_id=scan_id,
            vuln_type=vuln_type,
            severity=severity,
            cwe_id=cwe_id,
            description=description,
            file_path=file_path,
            line_number=line_number,
            status=status,
            owasp_category=owasp_category,
        )

        finding_create_request.additional_properties = d
        return finding_create_request

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
