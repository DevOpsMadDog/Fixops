from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.kpi_category import KPICategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.kpi_record_request_metadata import KPIRecordRequestMetadata


T = TypeVar("T", bound="KPIRecordRequest")


@_attrs_define
class KPIRecordRequest:
    """Request body for recording a KPI value.

    Attributes:
        name (str): KPI name (e.g. mttd_minutes)
        value (float): Numeric KPI value
        category (KPICategory): Category grouping for security KPIs.
        org_id (str | Unset): Organisation identifier Default: 'default'.
        period (str | Unset): Reporting period label (e.g. 2026-04) Default: ''.
        metadata (KPIRecordRequestMetadata | Unset):
    """

    name: str
    value: float
    category: KPICategory
    org_id: str | Unset = "default"
    period: str | Unset = ""
    metadata: KPIRecordRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        value = self.value

        category = self.category.value

        org_id = self.org_id

        period = self.period

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "value": value,
                "category": category,
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
        from ..models.kpi_record_request_metadata import KPIRecordRequestMetadata

        d = dict(src_dict)
        name = d.pop("name")

        value = d.pop("value")

        category = KPICategory(d.pop("category"))

        org_id = d.pop("org_id", UNSET)

        period = d.pop("period", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: KPIRecordRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = KPIRecordRequestMetadata.from_dict(_metadata)

        kpi_record_request = cls(
            name=name,
            value=value,
            category=category,
            org_id=org_id,
            period=period,
            metadata=metadata,
        )

        kpi_record_request.additional_properties = d
        return kpi_record_request

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
