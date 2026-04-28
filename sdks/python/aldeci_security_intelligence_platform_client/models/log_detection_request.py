from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.log_detection_request_metadata_type_0 import LogDetectionRequestMetadataType0


T = TypeVar("T", bound="LogDetectionRequest")


@_attrs_define
class LogDetectionRequest:
    """
    Attributes:
        technique_id (str):
        source (str): e.g. 'ids', 'siem', 'edr'
        confidence (float | Unset):  Default: 0.8.
        metadata (LogDetectionRequestMetadataType0 | None | Unset):
    """

    technique_id: str
    source: str
    confidence: float | Unset = 0.8
    metadata: LogDetectionRequestMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.log_detection_request_metadata_type_0 import LogDetectionRequestMetadataType0

        technique_id = self.technique_id

        source = self.source

        confidence = self.confidence

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, LogDetectionRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "technique_id": technique_id,
                "source": source,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.log_detection_request_metadata_type_0 import LogDetectionRequestMetadataType0

        d = dict(src_dict)
        technique_id = d.pop("technique_id")

        source = d.pop("source")

        confidence = d.pop("confidence", UNSET)

        def _parse_metadata(data: object) -> LogDetectionRequestMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = LogDetectionRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(LogDetectionRequestMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        log_detection_request = cls(
            technique_id=technique_id,
            source=source,
            confidence=confidence,
            metadata=metadata,
        )

        log_detection_request.additional_properties = d
        return log_detection_request

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
