from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.provenance_level import ProvenanceLevel
from ..types import UNSET, Unset

T = TypeVar("T", bound="ProvenanceRecord")


@_attrs_define
class ProvenanceRecord:
    """SLSA provenance / build attestation for a component.

    Attributes:
        component_name (str):
        component_version (str):
        id (str | Unset):
        slsa_level (ProvenanceLevel | Unset): SLSA provenance levels.
        build_system (None | str | Unset): e.g. GitHub Actions, Jenkins
        build_config_uri (None | str | Unset):
        builder_id (None | str | Unset):
        source_uri (None | str | Unset):
        source_digest (None | str | Unset):
        attestation_payload (None | str | Unset): Raw attestation JSON
        signature_verified (bool | Unset):  Default: False.
        signature_keyid (None | str | Unset):
        sigstore_bundle (None | str | Unset):
        verification_errors (list[str] | Unset):
        verified_at (datetime.datetime | Unset):
    """

    component_name: str
    component_version: str
    id: str | Unset = UNSET
    slsa_level: ProvenanceLevel | Unset = UNSET
    build_system: None | str | Unset = UNSET
    build_config_uri: None | str | Unset = UNSET
    builder_id: None | str | Unset = UNSET
    source_uri: None | str | Unset = UNSET
    source_digest: None | str | Unset = UNSET
    attestation_payload: None | str | Unset = UNSET
    signature_verified: bool | Unset = False
    signature_keyid: None | str | Unset = UNSET
    sigstore_bundle: None | str | Unset = UNSET
    verification_errors: list[str] | Unset = UNSET
    verified_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        component_name = self.component_name

        component_version = self.component_version

        id = self.id

        slsa_level: str | Unset = UNSET
        if not isinstance(self.slsa_level, Unset):
            slsa_level = self.slsa_level.value

        build_system: None | str | Unset
        if isinstance(self.build_system, Unset):
            build_system = UNSET
        else:
            build_system = self.build_system

        build_config_uri: None | str | Unset
        if isinstance(self.build_config_uri, Unset):
            build_config_uri = UNSET
        else:
            build_config_uri = self.build_config_uri

        builder_id: None | str | Unset
        if isinstance(self.builder_id, Unset):
            builder_id = UNSET
        else:
            builder_id = self.builder_id

        source_uri: None | str | Unset
        if isinstance(self.source_uri, Unset):
            source_uri = UNSET
        else:
            source_uri = self.source_uri

        source_digest: None | str | Unset
        if isinstance(self.source_digest, Unset):
            source_digest = UNSET
        else:
            source_digest = self.source_digest

        attestation_payload: None | str | Unset
        if isinstance(self.attestation_payload, Unset):
            attestation_payload = UNSET
        else:
            attestation_payload = self.attestation_payload

        signature_verified = self.signature_verified

        signature_keyid: None | str | Unset
        if isinstance(self.signature_keyid, Unset):
            signature_keyid = UNSET
        else:
            signature_keyid = self.signature_keyid

        sigstore_bundle: None | str | Unset
        if isinstance(self.sigstore_bundle, Unset):
            sigstore_bundle = UNSET
        else:
            sigstore_bundle = self.sigstore_bundle

        verification_errors: list[str] | Unset = UNSET
        if not isinstance(self.verification_errors, Unset):
            verification_errors = self.verification_errors

        verified_at: str | Unset = UNSET
        if not isinstance(self.verified_at, Unset):
            verified_at = self.verified_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "component_name": component_name,
                "component_version": component_version,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if slsa_level is not UNSET:
            field_dict["slsa_level"] = slsa_level
        if build_system is not UNSET:
            field_dict["build_system"] = build_system
        if build_config_uri is not UNSET:
            field_dict["build_config_uri"] = build_config_uri
        if builder_id is not UNSET:
            field_dict["builder_id"] = builder_id
        if source_uri is not UNSET:
            field_dict["source_uri"] = source_uri
        if source_digest is not UNSET:
            field_dict["source_digest"] = source_digest
        if attestation_payload is not UNSET:
            field_dict["attestation_payload"] = attestation_payload
        if signature_verified is not UNSET:
            field_dict["signature_verified"] = signature_verified
        if signature_keyid is not UNSET:
            field_dict["signature_keyid"] = signature_keyid
        if sigstore_bundle is not UNSET:
            field_dict["sigstore_bundle"] = sigstore_bundle
        if verification_errors is not UNSET:
            field_dict["verification_errors"] = verification_errors
        if verified_at is not UNSET:
            field_dict["verified_at"] = verified_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        component_name = d.pop("component_name")

        component_version = d.pop("component_version")

        id = d.pop("id", UNSET)

        _slsa_level = d.pop("slsa_level", UNSET)
        slsa_level: ProvenanceLevel | Unset
        if isinstance(_slsa_level, Unset):
            slsa_level = UNSET
        else:
            slsa_level = ProvenanceLevel(_slsa_level)

        def _parse_build_system(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        build_system = _parse_build_system(d.pop("build_system", UNSET))

        def _parse_build_config_uri(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        build_config_uri = _parse_build_config_uri(d.pop("build_config_uri", UNSET))

        def _parse_builder_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        builder_id = _parse_builder_id(d.pop("builder_id", UNSET))

        def _parse_source_uri(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_uri = _parse_source_uri(d.pop("source_uri", UNSET))

        def _parse_source_digest(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_digest = _parse_source_digest(d.pop("source_digest", UNSET))

        def _parse_attestation_payload(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attestation_payload = _parse_attestation_payload(d.pop("attestation_payload", UNSET))

        signature_verified = d.pop("signature_verified", UNSET)

        def _parse_signature_keyid(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        signature_keyid = _parse_signature_keyid(d.pop("signature_keyid", UNSET))

        def _parse_sigstore_bundle(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sigstore_bundle = _parse_sigstore_bundle(d.pop("sigstore_bundle", UNSET))

        verification_errors = cast(list[str], d.pop("verification_errors", UNSET))

        _verified_at = d.pop("verified_at", UNSET)
        verified_at: datetime.datetime | Unset
        if isinstance(_verified_at, Unset):
            verified_at = UNSET
        else:
            verified_at = isoparse(_verified_at)

        provenance_record = cls(
            component_name=component_name,
            component_version=component_version,
            id=id,
            slsa_level=slsa_level,
            build_system=build_system,
            build_config_uri=build_config_uri,
            builder_id=builder_id,
            source_uri=source_uri,
            source_digest=source_digest,
            attestation_payload=attestation_payload,
            signature_verified=signature_verified,
            signature_keyid=signature_keyid,
            sigstore_bundle=sigstore_bundle,
            verification_errors=verification_errors,
            verified_at=verified_at,
        )

        provenance_record.additional_properties = d
        return provenance_record

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
