from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceVerifyRequest")


@_attrs_define
class EvidenceVerifyRequest:
    """Request body for the legacy POST /evidence/verify endpoint.

    Attributes:
        bundle_id (str): The evidence bundle ID to verify
        signature (None | str | Unset): Base64-encoded RSA signature (optional, will be read from manifest if not
            provided)
        fingerprint (None | str | Unset): Public key fingerprint (optional, will be read from manifest if not provided)
    """

    bundle_id: str
    signature: None | str | Unset = UNSET
    fingerprint: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle_id = self.bundle_id

        signature: None | str | Unset
        if isinstance(self.signature, Unset):
            signature = UNSET
        else:
            signature = self.signature

        fingerprint: None | str | Unset
        if isinstance(self.fingerprint, Unset):
            fingerprint = UNSET
        else:
            fingerprint = self.fingerprint

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bundle_id": bundle_id,
            }
        )
        if signature is not UNSET:
            field_dict["signature"] = signature
        if fingerprint is not UNSET:
            field_dict["fingerprint"] = fingerprint

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bundle_id = d.pop("bundle_id")

        def _parse_signature(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        signature = _parse_signature(d.pop("signature", UNSET))

        def _parse_fingerprint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fingerprint = _parse_fingerprint(d.pop("fingerprint", UNSET))

        evidence_verify_request = cls(
            bundle_id=bundle_id,
            signature=signature,
            fingerprint=fingerprint,
        )

        evidence_verify_request.additional_properties = d
        return evidence_verify_request

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
