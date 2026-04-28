from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.batch_kpi_item_metadata_type_0 import BatchKPIItemMetadataType0


T = TypeVar("T", bound="BatchKPIItem")


@_attrs_define
class BatchKPIItem:
    """
    Attributes:
        kpi_name (str):
        value (float):
        period (None | str | Unset):
        metadata (BatchKPIItemMetadataType0 | None | Unset):
    """

    kpi_name: str
    value: float
    period: None | str | Unset = UNSET
    metadata: BatchKPIItemMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.batch_kpi_item_metadata_type_0 import BatchKPIItemMetadataType0

        kpi_name = self.kpi_name

        value = self.value

        period: None | str | Unset
        if isinstance(self.period, Unset):
            period = UNSET
        else:
            period = self.period

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, BatchKPIItemMetadataType0):
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
        if period is not UNSET:
            field_dict["period"] = period
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.batch_kpi_item_metadata_type_0 import BatchKPIItemMetadataType0

        d = dict(src_dict)
        kpi_name = d.pop("kpi_name")

        value = d.pop("value")

        def _parse_period(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        period = _parse_period(d.pop("period", UNSET))

        def _parse_metadata(data: object) -> BatchKPIItemMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = BatchKPIItemMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BatchKPIItemMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        batch_kpi_item = cls(
            kpi_name=kpi_name,
            value=value,
            period=period,
            metadata=metadata,
        )

        batch_kpi_item.additional_properties = d
        return batch_kpi_item

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
