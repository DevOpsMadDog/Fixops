from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.record_kpi_request_metadata_type_0 import RecordKPIRequestMetadataType0


T = TypeVar("T", bound="RecordKPIRequest")


@_attrs_define
class RecordKPIRequest:
    """
    Attributes:
        kpi_name (str): One of: ['mttd_hours', 'mttr_hours', 'mttr_critical_hours', 'patch_compliance_pct',
            'vuln_density', 'sla_compliance_pct', 'false_positive_rate', 'open_critical_count', 'incidents_per_month',
            'posture_score']
        value (float): Numeric KPI value
        org_id (str | Unset): Organisation ID Default: 'default'.
        period (None | str | Unset): 'daily'|'weekly'|'monthly'
        metadata (None | RecordKPIRequestMetadataType0 | Unset):
    """

    kpi_name: str
    value: float
    org_id: str | Unset = "default"
    period: None | str | Unset = UNSET
    metadata: None | RecordKPIRequestMetadataType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.record_kpi_request_metadata_type_0 import RecordKPIRequestMetadataType0

        kpi_name = self.kpi_name

        value = self.value

        org_id = self.org_id

        period: None | str | Unset
        if isinstance(self.period, Unset):
            period = UNSET
        else:
            period = self.period

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, RecordKPIRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "kpi_name": kpi_name,
                "value": value,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if period is not UNSET:
            field_dict["period"] = period
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.record_kpi_request_metadata_type_0 import RecordKPIRequestMetadataType0

        d = dict(src_dict)
        kpi_name = d.pop("kpi_name")

        value = d.pop("value")

        org_id = d.pop("org_id", UNSET)

        def _parse_period(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        period = _parse_period(d.pop("period", UNSET))

        def _parse_metadata(data: object) -> None | RecordKPIRequestMetadataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = RecordKPIRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RecordKPIRequestMetadataType0 | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        record_kpi_request = cls(
            kpi_name=kpi_name,
            value=value,
            org_id=org_id,
            period=period,
            metadata=metadata,
        )

        record_kpi_request.additional_properties = d
        return record_kpi_request

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
