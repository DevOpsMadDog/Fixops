from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EvidenceVerifyResponse")


@_attrs_define
class EvidenceVerifyResponse:
    """Response from the legacy POST /evidence/verify endpoint.

    Attributes:
        bundle_id (str):
        verified (bool):
        fingerprint (None | str | Unset):
        signed_at (None | str | Unset):
        signature_algorithm (None | str | Unset):
        error (None | str | Unset):
    """

    bundle_id: str
    verified: bool
    fingerprint: None | str | Unset = UNSET
    signed_at: None | str | Unset = UNSET
    signature_algorithm: None | str | Unset = UNSET
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        bundle_id = self.bundle_id

        verified = self.verified

        fingerprint: None | str | Unset
        if isinstance(self.fingerprint, Unset):
            fingerprint = UNSET
        else:
            fingerprint = self.fingerprint

        signed_at: None | str | Unset
        if isinstance(self.signed_at, Unset):
            signed_at = UNSET
        else:
            signed_at = self.signed_at

        signature_algorithm: None | str | Unset
        if isinstance(self.signature_algorithm, Unset):
            signature_algorithm = UNSET
        else:
            signature_algorithm = self.signature_algorithm

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "bundle_id": bundle_id,
                "verified": verified,
            }
        )
        if fingerprint is not UNSET:
            field_dict["fingerprint"] = fingerprint
        if signed_at is not UNSET:
            field_dict["signed_at"] = signed_at
        if signature_algorithm is not UNSET:
            field_dict["signature_algorithm"] = signature_algorithm
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        bundle_id = d.pop("bundle_id")

        verified = d.pop("verified")

        def _parse_fingerprint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fingerprint = _parse_fingerprint(d.pop("fingerprint", UNSET))

        def _parse_signed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        signed_at = _parse_signed_at(d.pop("signed_at", UNSET))

        def _parse_signature_algorithm(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        signature_algorithm = _parse_signature_algorithm(d.pop("signature_algorithm", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        evidence_verify_response = cls(
            bundle_id=bundle_id,
            verified=verified,
            fingerprint=fingerprint,
            signed_at=signed_at,
            signature_algorithm=signature_algorithm,
            error=error,
        )

        evidence_verify_response.additional_properties = d
        return evidence_verify_response

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
