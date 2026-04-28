from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ide_config_response_features import IDEConfigResponseFeatures


T = TypeVar("T", bound="IDEConfigResponse")


@_attrs_define
class IDEConfigResponse:
    """Response model for IDE configuration.

    Attributes:
        api_endpoint (str):
        supported_languages (list[str]):
        features (IDEConfigResponseFeatures):
        version (str | Unset):  Default: '2.0.0'.
        analysis_capabilities (list[str] | Unset):
    """

    api_endpoint: str
    supported_languages: list[str]
    features: IDEConfigResponseFeatures
    version: str | Unset = "2.0.0"
    analysis_capabilities: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        api_endpoint = self.api_endpoint

        supported_languages = self.supported_languages

        features = self.features.to_dict()

        version = self.version

        analysis_capabilities: list[str] | Unset = UNSET
        if not isinstance(self.analysis_capabilities, Unset):
            analysis_capabilities = self.analysis_capabilities

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "api_endpoint": api_endpoint,
                "supported_languages": supported_languages,
                "features": features,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if analysis_capabilities is not UNSET:
            field_dict["analysis_capabilities"] = analysis_capabilities

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ide_config_response_features import IDEConfigResponseFeatures

        d = dict(src_dict)
        api_endpoint = d.pop("api_endpoint")

        supported_languages = cast(list[str], d.pop("supported_languages"))

        features = IDEConfigResponseFeatures.from_dict(d.pop("features"))

        version = d.pop("version", UNSET)

        analysis_capabilities = cast(list[str], d.pop("analysis_capabilities", UNSET))

        ide_config_response = cls(
            api_endpoint=api_endpoint,
            supported_languages=supported_languages,
            features=features,
            version=version,
            analysis_capabilities=analysis_capabilities,
        )

        ide_config_response.additional_properties = d
        return ide_config_response

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
