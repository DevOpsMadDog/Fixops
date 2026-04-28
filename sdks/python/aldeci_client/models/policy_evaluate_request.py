from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.policy_evaluate_request_config_type_0 import PolicyEvaluateRequestConfigType0
    from ..models.policy_evaluate_request_manifest_type_0 import PolicyEvaluateRequestManifestType0


T = TypeVar("T", bound="PolicyEvaluateRequest")


@_attrs_define
class PolicyEvaluateRequest:
    """POST /policies/evaluate — evaluate image against runtime policies.

    Attributes:
        image_ref (str):
        manifest (None | PolicyEvaluateRequestManifestType0 | Unset):
        config (None | PolicyEvaluateRequestConfigType0 | Unset):
        policy_id (None | str | Unset):
    """

    image_ref: str
    manifest: None | PolicyEvaluateRequestManifestType0 | Unset = UNSET
    config: None | PolicyEvaluateRequestConfigType0 | Unset = UNSET
    policy_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.policy_evaluate_request_config_type_0 import PolicyEvaluateRequestConfigType0
        from ..models.policy_evaluate_request_manifest_type_0 import PolicyEvaluateRequestManifestType0

        image_ref = self.image_ref

        manifest: dict[str, Any] | None | Unset
        if isinstance(self.manifest, Unset):
            manifest = UNSET
        elif isinstance(self.manifest, PolicyEvaluateRequestManifestType0):
            manifest = self.manifest.to_dict()
        else:
            manifest = self.manifest

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, PolicyEvaluateRequestConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        policy_id: None | str | Unset
        if isinstance(self.policy_id, Unset):
            policy_id = UNSET
        else:
            policy_id = self.policy_id

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
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.policy_evaluate_request_config_type_0 import PolicyEvaluateRequestConfigType0
        from ..models.policy_evaluate_request_manifest_type_0 import PolicyEvaluateRequestManifestType0

        d = dict(src_dict)
        image_ref = d.pop("image_ref")

        def _parse_manifest(data: object) -> None | PolicyEvaluateRequestManifestType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                manifest_type_0 = PolicyEvaluateRequestManifestType0.from_dict(data)

                return manifest_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyEvaluateRequestManifestType0 | Unset, data)

        manifest = _parse_manifest(d.pop("manifest", UNSET))

        def _parse_config(data: object) -> None | PolicyEvaluateRequestConfigType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = PolicyEvaluateRequestConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyEvaluateRequestConfigType0 | Unset, data)

        config = _parse_config(d.pop("config", UNSET))

        def _parse_policy_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_id = _parse_policy_id(d.pop("policy_id", UNSET))

        policy_evaluate_request = cls(
            image_ref=image_ref,
            manifest=manifest,
            config=config,
            policy_id=policy_id,
        )

        policy_evaluate_request.additional_properties = d
        return policy_evaluate_request

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
