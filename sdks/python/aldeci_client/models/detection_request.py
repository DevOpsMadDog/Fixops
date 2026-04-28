from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.detection_request_metadata_type_0 import DetectionRequestMetadataType0


T = TypeVar("T", bound="DetectionRequest")


@_attrs_define
class DetectionRequest:
    """
    Attributes:
        org_id (str):
        technique_id (str):
        source (str):
        confidence (float | Unset):  Default: 0.5.
        metadata (DetectionRequestMetadataType0 | None | Unset):
    """

    org_id: str
    technique_id: str
    source: str
    confidence: float | Unset = 0.5
    metadata: DetectionRequestMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.detection_request_metadata_type_0 import DetectionRequestMetadataType0

        org_id = self.org_id

        technique_id = self.technique_id

        source = self.source

        confidence = self.confidence

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, DetectionRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
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
        from ..models.detection_request_metadata_type_0 import DetectionRequestMetadataType0

        d = dict(src_dict)
        org_id = d.pop("org_id")

        technique_id = d.pop("technique_id")

        source = d.pop("source")

        confidence = d.pop("confidence", UNSET)

        def _parse_metadata(data: object) -> DetectionRequestMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = DetectionRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DetectionRequestMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        detection_request = cls(
            org_id=org_id,
            technique_id=technique_id,
            source=source,
            confidence=confidence,
            metadata=metadata,
        )

        detection_request.additional_properties = d
        return detection_request

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
