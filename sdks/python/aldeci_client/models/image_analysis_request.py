from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.image_analysis_request_config_type_0 import ImageAnalysisRequestConfigType0
    from ..models.image_analysis_request_manifest_type_0 import ImageAnalysisRequestManifestType0


T = TypeVar("T", bound="ImageAnalysisRequest")


@_attrs_define
class ImageAnalysisRequest:
    """POST /images/analyse — analyse a container image from manifest/config blobs.

    Attributes:
        image_ref (str):
        manifest (ImageAnalysisRequestManifestType0 | None | Unset):
        config (ImageAnalysisRequestConfigType0 | None | Unset):
    """

    image_ref: str
    manifest: ImageAnalysisRequestManifestType0 | None | Unset = UNSET
    config: ImageAnalysisRequestConfigType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.image_analysis_request_config_type_0 import ImageAnalysisRequestConfigType0
        from ..models.image_analysis_request_manifest_type_0 import ImageAnalysisRequestManifestType0

        image_ref = self.image_ref

        manifest: dict[str, Any] | None | Unset
        if isinstance(self.manifest, Unset):
            manifest = UNSET
        elif isinstance(self.manifest, ImageAnalysisRequestManifestType0):
            manifest = self.manifest.to_dict()
        else:
            manifest = self.manifest

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, ImageAnalysisRequestConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "image_ref": image_ref,
            }
        )
        if manifest is not UNSET:
            field_dict["manifest"] = manifest
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.image_analysis_request_config_type_0 import ImageAnalysisRequestConfigType0
        from ..models.image_analysis_request_manifest_type_0 import ImageAnalysisRequestManifestType0

        d = dict(src_dict)
        image_ref = d.pop("image_ref")

        def _parse_manifest(data: object) -> ImageAnalysisRequestManifestType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                manifest_type_0 = ImageAnalysisRequestManifestType0.from_dict(data)

                return manifest_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ImageAnalysisRequestManifestType0 | None | Unset, data)

        manifest = _parse_manifest(d.pop("manifest", UNSET))

        def _parse_config(data: object) -> ImageAnalysisRequestConfigType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = ImageAnalysisRequestConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ImageAnalysisRequestConfigType0 | None | Unset, data)

        config = _parse_config(d.pop("config", UNSET))

        image_analysis_request = cls(
            image_ref=image_ref,
            manifest=manifest,
            config=config,
        )

        image_analysis_request.additional_properties = d
        return image_analysis_request

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
