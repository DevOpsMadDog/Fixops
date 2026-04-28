from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="RawIngestResult")


@_attrs_define
class RawIngestResult:
    """Response for POST /api/v1/connectors/ingest/raw.

    Attributes:
        ingest_id (str): Unique ID for this raw ingest
        scan_type (str): Scanner type (e.g. 'sarif', 'json')
        product_name (str): Product/project name
        timestamp (datetime.datetime): When ingest was processed
        parsed_findings_count (int): Number of findings parsed
        errors (list[str] | Unset): Parsing errors
        defectdojo_import_id (None | str | Unset): DefectDojo import ID (if applicable)
    """

    ingest_id: str
    scan_type: str
    product_name: str
    timestamp: datetime.datetime
    parsed_findings_count: int
    errors: list[str] | Unset = UNSET
    defectdojo_import_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ingest_id = self.ingest_id

        scan_type = self.scan_type

        product_name = self.product_name

        timestamp = self.timestamp.isoformat()

        parsed_findings_count = self.parsed_findings_count

        errors: list[str] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = self.errors

        defectdojo_import_id: None | str | Unset
        if isinstance(self.defectdojo_import_id, Unset):
            defectdojo_import_id = UNSET
        else:
            defectdojo_import_id = self.defectdojo_import_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ingest_id": ingest_id,
                "scan_type": scan_type,
                "product_name": product_name,
                "timestamp": timestamp,
                "parsed_findings_count": parsed_findings_count,
            }
        )
        if errors is not UNSET:
            field_dict["errors"] = errors
        if defectdojo_import_id is not UNSET:
            field_dict["defectdojo_import_id"] = defectdojo_import_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ingest_id = d.pop("ingest_id")

        scan_type = d.pop("scan_type")

        product_name = d.pop("product_name")

        timestamp = isoparse(d.pop("timestamp"))

        parsed_findings_count = d.pop("parsed_findings_count")

        errors = cast(list[str], d.pop("errors", UNSET))

        def _parse_defectdojo_import_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        defectdojo_import_id = _parse_defectdojo_import_id(d.pop("defectdojo_import_id", UNSET))

        raw_ingest_result = cls(
            ingest_id=ingest_id,
            scan_type=scan_type,
            product_name=product_name,
            timestamp=timestamp,
            parsed_findings_count=parsed_findings_count,
            errors=errors,
            defectdojo_import_id=defectdojo_import_id,
        )

        raw_ingest_result.additional_properties = d
        return raw_ingest_result

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
