from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.export_io_cs_response_bundle import ExportIOCsResponseBundle


T = TypeVar("T", bound="ExportIOCsResponse")


@_attrs_define
class ExportIOCsResponse:
    """
    Attributes:
        bundle (ExportIOCsResponseBundle):
        count (int):
    """

    bundle: ExportIOCsResponseBundle
    count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle = self.bundle.to_dict()

        count = self.count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bundle": bundle,
                "count": count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.export_io_cs_response_bundle import ExportIOCsResponseBundle

        d = dict(src_dict)
        bundle = ExportIOCsResponseBundle.from_dict(d.pop("bundle"))

        count = d.pop("count")

        export_io_cs_response = cls(
            bundle=bundle,
            count=count,
        )

        export_io_cs_response.additional_properties = d
        return export_io_cs_response

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
