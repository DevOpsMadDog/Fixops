from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BundleVerificationResult")


@_attrs_define
class BundleVerificationResult:
    """Response from POST /evidence/bundles/{bundle_id}/verify.

    This is the shape the EvidenceBundles UI expects (VerificationResult type).

        Attributes:
            valid (bool): Overall verification result
            hash_match (bool): Whether the content hash matches
            signature_valid (bool): Whether the cryptographic signature is valid
            timestamp (str): ISO-8601 timestamp of verification
            certificate_chain (list[str]): Certificate chain used for signing
            issuer (str): Issuer of the signing certificate
    """

    valid: bool
    hash_match: bool
    signature_valid: bool
    timestamp: str
    certificate_chain: list[str]
    issuer: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        valid = self.valid

        hash_match = self.hash_match

        signature_valid = self.signature_valid

        timestamp = self.timestamp

        certificate_chain = self.certificate_chain

        issuer = self.issuer

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "valid": valid,
                "hash_match": hash_match,
                "signature_valid": signature_valid,
                "timestamp": timestamp,
                "certificate_chain": certificate_chain,
                "issuer": issuer,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        valid = d.pop("valid")

        hash_match = d.pop("hash_match")

        signature_valid = d.pop("signature_valid")

        timestamp = d.pop("timestamp")

        certificate_chain = cast(list[str], d.pop("certificate_chain"))

        issuer = d.pop("issuer")

        bundle_verification_result = cls(
            valid=valid,
            hash_match=hash_match,
            signature_valid=signature_valid,
            timestamp=timestamp,
            certificate_chain=certificate_chain,
            issuer=issuer,
        )

        bundle_verification_result.additional_properties = d
        return bundle_verification_result

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
