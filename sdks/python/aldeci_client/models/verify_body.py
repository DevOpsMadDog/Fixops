from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.verify_body_export_filter import VerifyBodyExportFilter


T = TypeVar("T", bound="VerifyBody")


@_attrs_define
class VerifyBody:
    """
    Attributes:
        export_filter (VerifyBodyExportFilter | Unset):
    """

    export_filter: VerifyBodyExportFilter | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        export_filter: dict[str, Any] | Unset = UNSET
        if not isinstance(self.export_filter, Unset):
            export_filter = self.export_filter.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if export_filter is not UNSET:
            field_dict["export_filter"] = export_filter

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.verify_body_export_filter import VerifyBodyExportFilter

        d = dict(src_dict)
        _export_filter = d.pop("export_filter", UNSET)
        export_filter: VerifyBodyExportFilter | Unset
        if isinstance(_export_filter, Unset):
            export_filter = UNSET
        else:
            export_filter = VerifyBodyExportFilter.from_dict(_export_filter)

        verify_body = cls(
            export_filter=export_filter,
        )

        verify_body.additional_properties = d
        return verify_body

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
