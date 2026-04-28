from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.relate_request_properties_type_0 import RelateRequestPropertiesType0


T = TypeVar("T", bound="RelateRequest")


@_attrs_define
class RelateRequest:
    """Create relationship request.

    Attributes:
        source_id (str):
        target_id (str):
        rel_type (str):
        confidence (float | None | Unset):  Default: 1.0.
        properties (None | RelateRequestPropertiesType0 | Unset):
    """

    source_id: str
    target_id: str
    rel_type: str
    confidence: float | None | Unset = 1.0
    properties: None | RelateRequestPropertiesType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.relate_request_properties_type_0 import RelateRequestPropertiesType0

        source_id = self.source_id

        target_id = self.target_id

        rel_type = self.rel_type

        confidence: float | None | Unset
        if isinstance(self.confidence, Unset):
            confidence = UNSET
        else:
            confidence = self.confidence

        properties: dict[str, Any] | None | Unset
        if isinstance(self.properties, Unset):
            properties = UNSET
        elif isinstance(self.properties, RelateRequestPropertiesType0):
            properties = self.properties.to_dict()
        else:
            properties = self.properties

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_id": source_id,
                "target_id": target_id,
                "rel_type": rel_type,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if properties is not UNSET:
            field_dict["properties"] = properties

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.relate_request_properties_type_0 import RelateRequestPropertiesType0

        d = dict(src_dict)
        source_id = d.pop("source_id")

        target_id = d.pop("target_id")

        rel_type = d.pop("rel_type")

        def _parse_confidence(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        confidence = _parse_confidence(d.pop("confidence", UNSET))

        def _parse_properties(data: object) -> None | RelateRequestPropertiesType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                properties_type_0 = RelateRequestPropertiesType0.from_dict(data)

                return properties_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RelateRequestPropertiesType0 | Unset, data)

        properties = _parse_properties(d.pop("properties", UNSET))

        relate_request = cls(
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            confidence=confidence,
            properties=properties,
        )

        relate_request.additional_properties = d
        return relate_request

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
