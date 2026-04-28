from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_request_metadata_type_0 import UpdateRequestMetadataType0


T = TypeVar("T", bound="UpdateRequest")


@_attrs_define
class UpdateRequest:
    """
    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        compliance_frameworks (list[str] | None | Unset):
        ssdlc_stages (list[str] | None | Unset):
        pricing_model (None | str | Unset):
        price (float | None | Unset):
        tags (list[str] | None | Unset):
        metadata (None | Unset | UpdateRequestMetadataType0):
        version (None | str | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    compliance_frameworks: list[str] | None | Unset = UNSET
    ssdlc_stages: list[str] | None | Unset = UNSET
    pricing_model: None | str | Unset = UNSET
    price: float | None | Unset = UNSET
    tags: list[str] | None | Unset = UNSET
    metadata: None | Unset | UpdateRequestMetadataType0 = UNSET
    version: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_request_metadata_type_0 import UpdateRequestMetadataType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        compliance_frameworks: list[str] | None | Unset
        if isinstance(self.compliance_frameworks, Unset):
            compliance_frameworks = UNSET
        elif isinstance(self.compliance_frameworks, list):
            compliance_frameworks = self.compliance_frameworks

        else:
            compliance_frameworks = self.compliance_frameworks

        ssdlc_stages: list[str] | None | Unset
        if isinstance(self.ssdlc_stages, Unset):
            ssdlc_stages = UNSET
        elif isinstance(self.ssdlc_stages, list):
            ssdlc_stages = self.ssdlc_stages

        else:
            ssdlc_stages = self.ssdlc_stages

        pricing_model: None | str | Unset
        if isinstance(self.pricing_model, Unset):
            pricing_model = UNSET
        else:
            pricing_model = self.pricing_model

        price: float | None | Unset
        if isinstance(self.price, Unset):
            price = UNSET
        else:
            price = self.price

        tags: list[str] | None | Unset
        if isinstance(self.tags, Unset):
            tags = UNSET
        elif isinstance(self.tags, list):
            tags = self.tags

        else:
            tags = self.tags

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, UpdateRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if compliance_frameworks is not UNSET:
            field_dict["compliance_frameworks"] = compliance_frameworks
        if ssdlc_stages is not UNSET:
            field_dict["ssdlc_stages"] = ssdlc_stages
        if pricing_model is not UNSET:
            field_dict["pricing_model"] = pricing_model
        if price is not UNSET:
            field_dict["price"] = price
        if tags is not UNSET:
            field_dict["tags"] = tags
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_request_metadata_type_0 import UpdateRequestMetadataType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_compliance_frameworks(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                compliance_frameworks_type_0 = cast(list[str], data)

                return compliance_frameworks_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        compliance_frameworks = _parse_compliance_frameworks(d.pop("compliance_frameworks", UNSET))

        def _parse_ssdlc_stages(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                ssdlc_stages_type_0 = cast(list[str], data)

                return ssdlc_stages_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        ssdlc_stages = _parse_ssdlc_stages(d.pop("ssdlc_stages", UNSET))

        def _parse_pricing_model(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        pricing_model = _parse_pricing_model(d.pop("pricing_model", UNSET))

        def _parse_price(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        price = _parse_price(d.pop("price", UNSET))

        def _parse_tags(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tags_type_0 = cast(list[str], data)

                return tags_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tags = _parse_tags(d.pop("tags", UNSET))

        def _parse_metadata(data: object) -> None | Unset | UpdateRequestMetadataType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = UpdateRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateRequestMetadataType0, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        update_request = cls(
            name=name,
            description=description,
            compliance_frameworks=compliance_frameworks,
            ssdlc_stages=ssdlc_stages,
            pricing_model=pricing_model,
            price=price,
            tags=tags,
            metadata=metadata,
            version=version,
        )

        update_request.additional_properties = d
        return update_request

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
