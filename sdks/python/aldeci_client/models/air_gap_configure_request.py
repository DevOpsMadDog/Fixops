from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.air_gap_configure_request_offline_data_paths_type_0 import AirGapConfigureRequestOfflineDataPathsType0


T = TypeVar("T", bound="AirGapConfigureRequest")


@_attrs_define
class AirGapConfigureRequest:
    """Request body for configuring air-gap mode settings.

    Attributes:
        mode (None | str | Unset): Air-gap mode: disabled | detected | configured | enforced
        classification_level (None | str | Unset): Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET
        allow_local_network (bool | None | Unset): Allow LAN traffic (e.g. for local Ollama/vLLM)
        allow_usb_import (bool | None | Unset): Allow data import from removable media
        fips_mode (None | str | Unset): FIPS enforcement: disabled | audit | enforced
        llm_backend (None | str | Unset): Local LLM backend: ollama | vllm | llamacpp | huggingface_local | none
        llm_endpoint (None | str | Unset): URL for the local LLM API (e.g. http://localhost:11434)
        llm_model (None | str | Unset): Model name to use (e.g. mistral:7b, llama3:8b)
        enabled_scanners (list[str] | None | Unset): List of scanner names to enable, or ['all'] for all 25
        offline_data_paths (AirGapConfigureRequestOfflineDataPathsType0 | None | Unset): Override paths for offline data
            (vuln_db, signatures, etc.)
        configured_by (None | str | Unset): Operator/user making the configuration change
    """

    mode: None | str | Unset = UNSET
    classification_level: None | str | Unset = UNSET
    allow_local_network: bool | None | Unset = UNSET
    allow_usb_import: bool | None | Unset = UNSET
    fips_mode: None | str | Unset = UNSET
    llm_backend: None | str | Unset = UNSET
    llm_endpoint: None | str | Unset = UNSET
    llm_model: None | str | Unset = UNSET
    enabled_scanners: list[str] | None | Unset = UNSET
    offline_data_paths: AirGapConfigureRequestOfflineDataPathsType0 | None | Unset = UNSET
    configured_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.air_gap_configure_request_offline_data_paths_type_0 import (
            AirGapConfigureRequestOfflineDataPathsType0,
        )

        mode: None | str | Unset
        if isinstance(self.mode, Unset):
            mode = UNSET
        else:
            mode = self.mode

        classification_level: None | str | Unset
        if isinstance(self.classification_level, Unset):
            classification_level = UNSET
        else:
            classification_level = self.classification_level

        allow_local_network: bool | None | Unset
        if isinstance(self.allow_local_network, Unset):
            allow_local_network = UNSET
        else:
            allow_local_network = self.allow_local_network

        allow_usb_import: bool | None | Unset
        if isinstance(self.allow_usb_import, Unset):
            allow_usb_import = UNSET
        else:
            allow_usb_import = self.allow_usb_import

        fips_mode: None | str | Unset
        if isinstance(self.fips_mode, Unset):
            fips_mode = UNSET
        else:
            fips_mode = self.fips_mode

        llm_backend: None | str | Unset
        if isinstance(self.llm_backend, Unset):
            llm_backend = UNSET
        else:
            llm_backend = self.llm_backend

        llm_endpoint: None | str | Unset
        if isinstance(self.llm_endpoint, Unset):
            llm_endpoint = UNSET
        else:
            llm_endpoint = self.llm_endpoint

        llm_model: None | str | Unset
        if isinstance(self.llm_model, Unset):
            llm_model = UNSET
        else:
            llm_model = self.llm_model

        enabled_scanners: list[str] | None | Unset
        if isinstance(self.enabled_scanners, Unset):
            enabled_scanners = UNSET
        elif isinstance(self.enabled_scanners, list):
            enabled_scanners = self.enabled_scanners

        else:
            enabled_scanners = self.enabled_scanners

        offline_data_paths: dict[str, Any] | None | Unset
        if isinstance(self.offline_data_paths, Unset):
            offline_data_paths = UNSET
        elif isinstance(self.offline_data_paths, AirGapConfigureRequestOfflineDataPathsType0):
            offline_data_paths = self.offline_data_paths.to_dict()
        else:
            offline_data_paths = self.offline_data_paths

        configured_by: None | str | Unset
        if isinstance(self.configured_by, Unset):
            configured_by = UNSET
        else:
            configured_by = self.configured_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if mode is not UNSET:
            field_dict["mode"] = mode
        if classification_level is not UNSET:
            field_dict["classification_level"] = classification_level
        if allow_local_network is not UNSET:
            field_dict["allow_local_network"] = allow_local_network
        if allow_usb_import is not UNSET:
            field_dict["allow_usb_import"] = allow_usb_import
        if fips_mode is not UNSET:
            field_dict["fips_mode"] = fips_mode
        if llm_backend is not UNSET:
            field_dict["llm_backend"] = llm_backend
        if llm_endpoint is not UNSET:
            field_dict["llm_endpoint"] = llm_endpoint
        if llm_model is not UNSET:
            field_dict["llm_model"] = llm_model
        if enabled_scanners is not UNSET:
            field_dict["enabled_scanners"] = enabled_scanners
        if offline_data_paths is not UNSET:
            field_dict["offline_data_paths"] = offline_data_paths
        if configured_by is not UNSET:
            field_dict["configured_by"] = configured_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.air_gap_configure_request_offline_data_paths_type_0 import (
            AirGapConfigureRequestOfflineDataPathsType0,
        )

        d = dict(src_dict)

        def _parse_mode(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mode = _parse_mode(d.pop("mode", UNSET))

        def _parse_classification_level(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        classification_level = _parse_classification_level(d.pop("classification_level", UNSET))

        def _parse_allow_local_network(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_local_network = _parse_allow_local_network(d.pop("allow_local_network", UNSET))

        def _parse_allow_usb_import(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        allow_usb_import = _parse_allow_usb_import(d.pop("allow_usb_import", UNSET))

        def _parse_fips_mode(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fips_mode = _parse_fips_mode(d.pop("fips_mode", UNSET))

        def _parse_llm_backend(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        llm_backend = _parse_llm_backend(d.pop("llm_backend", UNSET))

        def _parse_llm_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        llm_endpoint = _parse_llm_endpoint(d.pop("llm_endpoint", UNSET))

        def _parse_llm_model(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        llm_model = _parse_llm_model(d.pop("llm_model", UNSET))

        def _parse_enabled_scanners(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                enabled_scanners_type_0 = cast(list[str], data)

                return enabled_scanners_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        enabled_scanners = _parse_enabled_scanners(d.pop("enabled_scanners", UNSET))

        def _parse_offline_data_paths(data: object) -> AirGapConfigureRequestOfflineDataPathsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                offline_data_paths_type_0 = AirGapConfigureRequestOfflineDataPathsType0.from_dict(data)

                return offline_data_paths_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AirGapConfigureRequestOfflineDataPathsType0 | None | Unset, data)

        offline_data_paths = _parse_offline_data_paths(d.pop("offline_data_paths", UNSET))

        def _parse_configured_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        configured_by = _parse_configured_by(d.pop("configured_by", UNSET))

        air_gap_configure_request = cls(
            mode=mode,
            classification_level=classification_level,
            allow_local_network=allow_local_network,
            allow_usb_import=allow_usb_import,
            fips_mode=fips_mode,
            llm_backend=llm_backend,
            llm_endpoint=llm_endpoint,
            llm_model=llm_model,
            enabled_scanners=enabled_scanners,
            offline_data_paths=offline_data_paths,
            configured_by=configured_by,
        )

        air_gap_configure_request.additional_properties = d
        return air_gap_configure_request

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
