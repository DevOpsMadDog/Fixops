from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.risk_signal_severity import RiskSignalSeverity
from ..models.risk_signal_type import RiskSignalType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.record_signal_request_metadata import RecordSignalRequestMetadata


T = TypeVar("T", bound="RecordSignalRequest")


@_attrs_define
class RecordSignalRequest:
    """Request body for recording a monitoring signal.

    Attributes:
        signal_type (RiskSignalType):
        severity (RiskSignalSeverity):
        title (str):
        description (str):
        source (str | Unset):  Default: 'manual'.
        metadata (RecordSignalRequestMetadata | Unset):
    """

    signal_type: RiskSignalType
    severity: RiskSignalSeverity
    title: str
    description: str
    source: str | Unset = "manual"
    metadata: RecordSignalRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        signal_type = self.signal_type.value

        severity = self.severity.value

        title = self.title

        description = self.description

        source = self.source

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "signal_type": signal_type,
                "severity": severity,
                "title": title,
                "description": description,
            }
        )
        if source is not UNSET:
            field_dict["source"] = source
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.record_signal_request_metadata import RecordSignalRequestMetadata

        d = dict(src_dict)
        signal_type = RiskSignalType(d.pop("signal_type"))

        severity = RiskSignalSeverity(d.pop("severity"))

        title = d.pop("title")

        description = d.pop("description")

        source = d.pop("source", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: RecordSignalRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = RecordSignalRequestMetadata.from_dict(_metadata)

        record_signal_request = cls(
            signal_type=signal_type,
            severity=severity,
            title=title,
            description=description,
            source=source,
            metadata=metadata,
        )

        record_signal_request.additional_properties = d
        return record_signal_request

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
