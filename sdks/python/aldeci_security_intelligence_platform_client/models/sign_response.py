from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SignResponse")


@_attrs_define
class SignResponse:
    """
    Attributes:
        signature_id (str):
        rsa_algorithm (str):
        mldsa_algorithm (str):
        content_hash (str):
        rsa_signature (str):
        mldsa_signature (str):
        worm_retention_until (str):
        verified (bool):
    """

    signature_id: str
    rsa_algorithm: str
    mldsa_algorithm: str
    content_hash: str
    rsa_signature: str
    mldsa_signature: str
    worm_retention_until: str
    verified: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        signature_id = self.signature_id

        rsa_algorithm = self.rsa_algorithm

        mldsa_algorithm = self.mldsa_algorithm

        content_hash = self.content_hash

        rsa_signature = self.rsa_signature

        mldsa_signature = self.mldsa_signature

        worm_retention_until = self.worm_retention_until

        verified = self.verified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "signature_id": signature_id,
                "rsa_algorithm": rsa_algorithm,
                "mldsa_algorithm": mldsa_algorithm,
                "content_hash": content_hash,
                "rsa_signature": rsa_signature,
                "mldsa_signature": mldsa_signature,
                "worm_retention_until": worm_retention_until,
                "verified": verified,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        signature_id = d.pop("signature_id")

        rsa_algorithm = d.pop("rsa_algorithm")

        mldsa_algorithm = d.pop("mldsa_algorithm")

        content_hash = d.pop("content_hash")

        rsa_signature = d.pop("rsa_signature")

        mldsa_signature = d.pop("mldsa_signature")

        worm_retention_until = d.pop("worm_retention_until")

        verified = d.pop("verified")

        sign_response = cls(
            signature_id=signature_id,
            rsa_algorithm=rsa_algorithm,
            mldsa_algorithm=mldsa_algorithm,
            content_hash=content_hash,
            rsa_signature=rsa_signature,
            mldsa_signature=mldsa_signature,
            worm_retention_until=worm_retention_until,
            verified=verified,
        )

        sign_response.additional_properties = d
        return sign_response

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
