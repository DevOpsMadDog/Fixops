from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_scan_request_findings_type_0_item import IngestScanRequestFindingsType0Item


T = TypeVar("T", bound="IngestScanRequest")


@_attrs_define
class IngestScanRequest:
    """Validated scan ingest request.

    Attributes:
        scan_id (str):
        org_id (None | str | Unset):
        scanner (None | str | Unset):
        findings (list[IngestScanRequestFindingsType0Item] | None | Unset):
    """

    scan_id: str
    org_id: None | str | Unset = UNSET
    scanner: None | str | Unset = UNSET
    findings: list[IngestScanRequestFindingsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_id = self.scan_id

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        scanner: None | str | Unset
        if isinstance(self.scanner, Unset):
            scanner = UNSET
        else:
            scanner = self.scanner

        findings: list[dict[str, Any]] | None | Unset
        if isinstance(self.findings, Unset):
            findings = UNSET
        elif isinstance(self.findings, list):
            findings = []
            for findings_type_0_item_data in self.findings:
                findings_type_0_item = findings_type_0_item_data.to_dict()
                findings.append(findings_type_0_item)

        else:
            findings = self.findings

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_id": scan_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if scanner is not UNSET:
            field_dict["scanner"] = scanner
        if findings is not UNSET:
            field_dict["findings"] = findings

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_scan_request_findings_type_0_item import IngestScanRequestFindingsType0Item

        d = dict(src_dict)
        scan_id = d.pop("scan_id")

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        def _parse_scanner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanner = _parse_scanner(d.pop("scanner", UNSET))

        def _parse_findings(data: object) -> list[IngestScanRequestFindingsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                findings_type_0 = []
                _findings_type_0 = data
                for findings_type_0_item_data in _findings_type_0:
                    findings_type_0_item = IngestScanRequestFindingsType0Item.from_dict(findings_type_0_item_data)

                    findings_type_0.append(findings_type_0_item)

                return findings_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[IngestScanRequestFindingsType0Item] | None | Unset, data)

        findings = _parse_findings(d.pop("findings", UNSET))

        ingest_scan_request = cls(
            scan_id=scan_id,
            org_id=org_id,
            scanner=scanner,
            findings=findings,
        )

        ingest_scan_request.additional_properties = d
        return ingest_scan_request

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
