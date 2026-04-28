from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.drift_detect_request_config_type_0 import DriftDetectRequestConfigType0
    from ..models.drift_detect_request_manifest_type_0 import DriftDetectRequestManifestType0
    from ..models.drift_detect_request_runtime_state import DriftDetectRequestRuntimeState


T = TypeVar("T", bound="DriftDetectRequest")


@_attrs_define
class DriftDetectRequest:
    """POST /drift/detect — compare running container against image baseline.

    Attributes:
        container_id (str):
        image_ref (str):
        manifest (DriftDetectRequestManifestType0 | None | Unset):
        config (DriftDetectRequestConfigType0 | None | Unset):
        runtime_state (DriftDetectRequestRuntimeState | Unset): Keys: files (Dict[path,sha256]), processes (List[str]),
            env_vars (List[str]), network_connections (List[str])
    """

    container_id: str
    image_ref: str
    manifest: DriftDetectRequestManifestType0 | None | Unset = UNSET
    config: DriftDetectRequestConfigType0 | None | Unset = UNSET
    runtime_state: DriftDetectRequestRuntimeState | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.drift_detect_request_config_type_0 import DriftDetectRequestConfigType0
        from ..models.drift_detect_request_manifest_type_0 import DriftDetectRequestManifestType0

        container_id = self.container_id

        image_ref = self.image_ref

        manifest: dict[str, Any] | None | Unset
        if isinstance(self.manifest, Unset):
            manifest = UNSET
        elif isinstance(self.manifest, DriftDetectRequestManifestType0):
            manifest = self.manifest.to_dict()
        else:
            manifest = self.manifest

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, DriftDetectRequestConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        runtime_state: dict[str, Any] | Unset = UNSET
        if not isinstance(self.runtime_state, Unset):
            runtime_state = self.runtime_state.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "container_id": container_id,
                "image_ref": image_ref,
            }
        )
        if manifest is not UNSET:
            field_dict["manifest"] = manifest
        if config is not UNSET:
            field_dict["config"] = config
        if runtime_state is not UNSET:
            field_dict["runtime_state"] = runtime_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.drift_detect_request_config_type_0 import DriftDetectRequestConfigType0
        from ..models.drift_detect_request_manifest_type_0 import DriftDetectRequestManifestType0
        from ..models.drift_detect_request_runtime_state import DriftDetectRequestRuntimeState

        d = dict(src_dict)
        container_id = d.pop("container_id")

        image_ref = d.pop("image_ref")

        def _parse_manifest(data: object) -> DriftDetectRequestManifestType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                manifest_type_0 = DriftDetectRequestManifestType0.from_dict(data)

                return manifest_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DriftDetectRequestManifestType0 | None | Unset, data)

        manifest = _parse_manifest(d.pop("manifest", UNSET))

        def _parse_config(data: object) -> DriftDetectRequestConfigType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = DriftDetectRequestConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DriftDetectRequestConfigType0 | None | Unset, data)

        config = _parse_config(d.pop("config", UNSET))

        _runtime_state = d.pop("runtime_state", UNSET)
        runtime_state: DriftDetectRequestRuntimeState | Unset
        if isinstance(_runtime_state, Unset):
            runtime_state = UNSET
        else:
            runtime_state = DriftDetectRequestRuntimeState.from_dict(_runtime_state)

        drift_detect_request = cls(
            container_id=container_id,
            image_ref=image_ref,
            manifest=manifest,
            config=config,
            runtime_state=runtime_state,
        )

        drift_detect_request.additional_properties = d
        return drift_detect_request

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
