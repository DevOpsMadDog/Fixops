from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.verify_request_signature import VerifyRequestSignature


T = TypeVar("T", bound="VerifyRequest")


@_attrs_define
class VerifyRequest:
    """
    Attributes:
        content (str): Original content
        signature (VerifyRequestSignature): HybridSignature envelope
    """

    content: str
    signature: VerifyRequestSignature
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content = self.content

        signature = self.signature.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "content": content,
                "signature": signature,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.verify_request_signature import VerifyRequestSignature

        d = dict(src_dict)
        content = d.pop("content")

        signature = VerifyRequestSignature.from_dict(d.pop("signature"))

        verify_request = cls(
            content=content,
            signature=signature,
        )

        verify_request.additional_properties = d
        return verify_request

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
