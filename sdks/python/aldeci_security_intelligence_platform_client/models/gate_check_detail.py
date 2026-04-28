from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.gate_check_detail_metadata import GateCheckDetailMetadata


T = TypeVar("T", bound="GateCheckDetail")


@_attrs_define
class GateCheckDetail:
    """Individual check result within a gate evaluation.

    Attributes:
        name (str):
        status (str):
        detail (str):
        count (int | Unset):  Default: 0.
        metadata (GateCheckDetailMetadata | Unset):
    """

    name: str
    status: str
    detail: str
    count: int | Unset = 0
    metadata: GateCheckDetailMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        status = self.status

        detail = self.detail

        count = self.count

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "status": status,
                "detail": detail,
            }
        )
        if count is not UNSET:
            field_dict["count"] = count
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gate_check_detail_metadata import GateCheckDetailMetadata

        d = dict(src_dict)
        name = d.pop("name")

        status = d.pop("status")

        detail = d.pop("detail")

        count = d.pop("count", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: GateCheckDetailMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = GateCheckDetailMetadata.from_dict(_metadata)

        gate_check_detail = cls(
            name=name,
            status=status,
            detail=detail,
            count=count,
            metadata=metadata,
        )

        gate_check_detail.additional_properties = d
        return gate_check_detail

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
