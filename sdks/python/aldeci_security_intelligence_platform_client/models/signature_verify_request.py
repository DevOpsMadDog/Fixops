from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.signature_verify_request_signature_data_type_0 import SignatureVerifyRequestSignatureDataType0


T = TypeVar("T", bound="SignatureVerifyRequest")


@_attrs_define
class SignatureVerifyRequest:
    """POST /images/verify-signature — verify image signing.

    Attributes:
        image_ref (str):
        signature_data (None | SignatureVerifyRequestSignatureDataType0 | Unset):
        scheme (str | Unset):  Default: 'cosign'.
    """

    image_ref: str
    signature_data: None | SignatureVerifyRequestSignatureDataType0 | Unset = UNSET
    scheme: str | Unset = "cosign"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.signature_verify_request_signature_data_type_0 import SignatureVerifyRequestSignatureDataType0

        image_ref = self.image_ref

        signature_data: dict[str, Any] | None | Unset
        if isinstance(self.signature_data, Unset):
            signature_data = UNSET
        elif isinstance(self.signature_data, SignatureVerifyRequestSignatureDataType0):
            signature_data = self.signature_data.to_dict()
        else:
            signature_data = self.signature_data

        scheme = self.scheme

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "image_ref": image_ref,
            }
        )
        if signature_data is not UNSET:
            field_dict["signature_data"] = signature_data
        if scheme is not UNSET:
            field_dict["scheme"] = scheme

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.signature_verify_request_signature_data_type_0 import SignatureVerifyRequestSignatureDataType0

        d = dict(src_dict)
        image_ref = d.pop("image_ref")

        def _parse_signature_data(data: object) -> None | SignatureVerifyRequestSignatureDataType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                signature_data_type_0 = SignatureVerifyRequestSignatureDataType0.from_dict(data)

                return signature_data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SignatureVerifyRequestSignatureDataType0 | Unset, data)

        signature_data = _parse_signature_data(d.pop("signature_data", UNSET))

        scheme = d.pop("scheme", UNSET)

        signature_verify_request = cls(
            image_ref=image_ref,
            signature_data=signature_data,
            scheme=scheme,
        )

        signature_verify_request.additional_properties = d
        return signature_verify_request

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
