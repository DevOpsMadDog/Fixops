from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ArtifactRequest")


@_attrs_define
class ArtifactRequest:
    """
    Attributes:
        artifact_ref (str): Registry path / file path / package ref
        artifact_type (str): container-image|binary|package|sbom|attestation
        sha256 (str): SHA-256 of artifact
        step_id (None | str | Unset): Producing step_id (optional)
        size_bytes (int | Unset):  Default: 0.
        signed_by (str | Unset): Signer identity (cosign sub, KMS key) Default: ''.
        signature_algo (str | Unset): e.g. sigstore, rsa-sha256, ed25519 Default: ''.
    """

    artifact_ref: str
    artifact_type: str
    sha256: str
    step_id: None | str | Unset = UNSET
    size_bytes: int | Unset = 0
    signed_by: str | Unset = ""
    signature_algo: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        artifact_ref = self.artifact_ref

        artifact_type = self.artifact_type

        sha256 = self.sha256

        step_id: None | str | Unset
        if isinstance(self.step_id, Unset):
            step_id = UNSET
        else:
            step_id = self.step_id

        size_bytes = self.size_bytes

        signed_by = self.signed_by

        signature_algo = self.signature_algo

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "artifact_ref": artifact_ref,
                "artifact_type": artifact_type,
                "sha256": sha256,
            }
        )
        if step_id is not UNSET:
            field_dict["step_id"] = step_id
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if signed_by is not UNSET:
            field_dict["signed_by"] = signed_by
        if signature_algo is not UNSET:
            field_dict["signature_algo"] = signature_algo

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        artifact_ref = d.pop("artifact_ref")

        artifact_type = d.pop("artifact_type")

        sha256 = d.pop("sha256")

        def _parse_step_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        step_id = _parse_step_id(d.pop("step_id", UNSET))

        size_bytes = d.pop("size_bytes", UNSET)

        signed_by = d.pop("signed_by", UNSET)

        signature_algo = d.pop("signature_algo", UNSET)

        artifact_request = cls(
            artifact_ref=artifact_ref,
            artifact_type=artifact_type,
            sha256=sha256,
            step_id=step_id,
            size_bytes=size_bytes,
            signed_by=signed_by,
            signature_algo=signature_algo,
        )

        artifact_request.additional_properties = d
        return artifact_request

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
