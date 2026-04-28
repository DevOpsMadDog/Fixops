from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.registry_scan_request_images_type_0_item import RegistryScanRequestImagesType0Item
    from ..models.registry_scan_request_registry_metadata_type_0 import RegistryScanRequestRegistryMetadataType0


T = TypeVar("T", bound="RegistryScanRequest")


@_attrs_define
class RegistryScanRequest:
    """POST /registries/scan — assess registry security posture.

    Attributes:
        registry_url (str):
        registry_metadata (None | RegistryScanRequestRegistryMetadataType0 | Unset):
        images (list[RegistryScanRequestImagesType0Item] | None | Unset):
    """

    registry_url: str
    registry_metadata: None | RegistryScanRequestRegistryMetadataType0 | Unset = UNSET
    images: list[RegistryScanRequestImagesType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.registry_scan_request_registry_metadata_type_0 import RegistryScanRequestRegistryMetadataType0

        registry_url = self.registry_url

        registry_metadata: dict[str, Any] | None | Unset
        if isinstance(self.registry_metadata, Unset):
            registry_metadata = UNSET
        elif isinstance(self.registry_metadata, RegistryScanRequestRegistryMetadataType0):
            registry_metadata = self.registry_metadata.to_dict()
        else:
            registry_metadata = self.registry_metadata

        images: list[dict[str, Any]] | None | Unset
        if isinstance(self.images, Unset):
            images = UNSET
        elif isinstance(self.images, list):
            images = []
            for images_type_0_item_data in self.images:
                images_type_0_item = images_type_0_item_data.to_dict()
                images.append(images_type_0_item)

        else:
            images = self.images

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "registry_url": registry_url,
            }
        )
        if registry_metadata is not UNSET:
            field_dict["registry_metadata"] = registry_metadata
        if images is not UNSET:
            field_dict["images"] = images

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.registry_scan_request_images_type_0_item import RegistryScanRequestImagesType0Item
        from ..models.registry_scan_request_registry_metadata_type_0 import RegistryScanRequestRegistryMetadataType0

        d = dict(src_dict)
        registry_url = d.pop("registry_url")

        def _parse_registry_metadata(data: object) -> None | RegistryScanRequestRegistryMetadataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                registry_metadata_type_0 = RegistryScanRequestRegistryMetadataType0.from_dict(data)

                return registry_metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RegistryScanRequestRegistryMetadataType0 | Unset, data)

        registry_metadata = _parse_registry_metadata(d.pop("registry_metadata", UNSET))

        def _parse_images(data: object) -> list[RegistryScanRequestImagesType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                images_type_0 = []
                _images_type_0 = data
                for images_type_0_item_data in _images_type_0:
                    images_type_0_item = RegistryScanRequestImagesType0Item.from_dict(images_type_0_item_data)

                    images_type_0.append(images_type_0_item)

                return images_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[RegistryScanRequestImagesType0Item] | None | Unset, data)

        images = _parse_images(d.pop("images", UNSET))

        registry_scan_request = cls(
            registry_url=registry_url,
            registry_metadata=registry_metadata,
            images=images,
        )

        registry_scan_request.additional_properties = d
        return registry_scan_request

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
