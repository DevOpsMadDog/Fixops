from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.sync_finding_request_finding_data import SyncFindingRequestFindingData


T = TypeVar("T", bound="SyncFindingRequest")


@_attrs_define
class SyncFindingRequest:
    """
    Attributes:
        finding_id (str): Unique finding identifier
        finding_data (SyncFindingRequestFindingData): Finding fields: title, severity, description, cve_id, source, etc.
    """

    finding_id: str
    finding_data: SyncFindingRequestFindingData
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        finding_data = self.finding_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "finding_data": finding_data,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sync_finding_request_finding_data import SyncFindingRequestFindingData

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        finding_data = SyncFindingRequestFindingData.from_dict(d.pop("finding_data"))

        sync_finding_request = cls(
            finding_id=finding_id,
            finding_data=finding_data,
        )

        sync_finding_request.additional_properties = d
        return sync_finding_request

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
