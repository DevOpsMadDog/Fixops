from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_alert_request_raw_alert_json_type_0 import IngestAlertRequestRawAlertJsonType0


T = TypeVar("T", bound="IngestAlertRequest")


@_attrs_define
class IngestAlertRequest:
    """
    Attributes:
        title (str): Short alert title
        source_system (str | Unset): siem | edr | ndr | cloud | waf | ids | firewall | custom Default: 'siem'.
        severity (str | Unset): critical | high | medium | low | info Default: 'medium'.
        raw_alert_json (IngestAlertRequestRawAlertJsonType0 | None | Unset): Raw alert payload from source system
    """

    title: str
    source_system: str | Unset = "siem"
    severity: str | Unset = "medium"
    raw_alert_json: IngestAlertRequestRawAlertJsonType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.ingest_alert_request_raw_alert_json_type_0 import IngestAlertRequestRawAlertJsonType0

        title = self.title

        source_system = self.source_system

        severity = self.severity

        raw_alert_json: dict[str, Any] | None | Unset
        if isinstance(self.raw_alert_json, Unset):
            raw_alert_json = UNSET
        elif isinstance(self.raw_alert_json, IngestAlertRequestRawAlertJsonType0):
            raw_alert_json = self.raw_alert_json.to_dict()
        else:
            raw_alert_json = self.raw_alert_json

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if source_system is not UNSET:
            field_dict["source_system"] = source_system
        if severity is not UNSET:
            field_dict["severity"] = severity
        if raw_alert_json is not UNSET:
            field_dict["raw_alert_json"] = raw_alert_json

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_alert_request_raw_alert_json_type_0 import IngestAlertRequestRawAlertJsonType0

        d = dict(src_dict)
        title = d.pop("title")

        source_system = d.pop("source_system", UNSET)

        severity = d.pop("severity", UNSET)

        def _parse_raw_alert_json(data: object) -> IngestAlertRequestRawAlertJsonType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                raw_alert_json_type_0 = IngestAlertRequestRawAlertJsonType0.from_dict(data)

                return raw_alert_json_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(IngestAlertRequestRawAlertJsonType0 | None | Unset, data)

        raw_alert_json = _parse_raw_alert_json(d.pop("raw_alert_json", UNSET))

        ingest_alert_request = cls(
            title=title,
            source_system=source_system,
            severity=severity,
            raw_alert_json=raw_alert_json,
        )

        ingest_alert_request.additional_properties = d
        return ingest_alert_request

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
