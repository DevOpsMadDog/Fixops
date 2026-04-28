from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.bulk_import_iocs_item import BulkImportIocsItem


T = TypeVar("T", bound="BulkImport")


@_attrs_define
class BulkImport:
    """
    Attributes:
        iocs (list[BulkImportIocsItem]):
    """

    iocs: list[BulkImportIocsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        iocs = []
        for iocs_item_data in self.iocs:
            iocs_item = iocs_item_data.to_dict()
            iocs.append(iocs_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "iocs": iocs,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_import_iocs_item import BulkImportIocsItem

        d = dict(src_dict)
        iocs = []
        _iocs = d.pop("iocs")
        for iocs_item_data in _iocs:
            iocs_item = BulkImportIocsItem.from_dict(iocs_item_data)

            iocs.append(iocs_item)

        bulk_import = cls(
            iocs=iocs,
        )

        bulk_import.additional_properties = d
        return bulk_import

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
