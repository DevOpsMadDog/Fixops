from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.product_signature_model_header_patterns import ProductSignatureModelHeaderPatterns
    from ..models.product_signature_model_status_code_hints import ProductSignatureModelStatusCodeHints


T = TypeVar("T", bound="ProductSignatureModel")


@_attrs_define
class ProductSignatureModel:
    """
    Attributes:
        name (str):
        header_patterns (ProductSignatureModelHeaderPatterns | Unset):
        body_patterns (list[str] | Unset):
        url_paths (list[str] | Unset):
        cookie_patterns (list[str] | Unset):
        status_code_hints (ProductSignatureModelStatusCodeHints | Unset):
    """

    name: str
    header_patterns: ProductSignatureModelHeaderPatterns | Unset = UNSET
    body_patterns: list[str] | Unset = UNSET
    url_paths: list[str] | Unset = UNSET
    cookie_patterns: list[str] | Unset = UNSET
    status_code_hints: ProductSignatureModelStatusCodeHints | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        header_patterns: dict[str, Any] | Unset = UNSET
        if not isinstance(self.header_patterns, Unset):
            header_patterns = self.header_patterns.to_dict()

        body_patterns: list[str] | Unset = UNSET
        if not isinstance(self.body_patterns, Unset):
            body_patterns = self.body_patterns

        url_paths: list[str] | Unset = UNSET
        if not isinstance(self.url_paths, Unset):
            url_paths = self.url_paths

        cookie_patterns: list[str] | Unset = UNSET
        if not isinstance(self.cookie_patterns, Unset):
            cookie_patterns = self.cookie_patterns

        status_code_hints: dict[str, Any] | Unset = UNSET
        if not isinstance(self.status_code_hints, Unset):
            status_code_hints = self.status_code_hints.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if header_patterns is not UNSET:
            field_dict["header_patterns"] = header_patterns
        if body_patterns is not UNSET:
            field_dict["body_patterns"] = body_patterns
        if url_paths is not UNSET:
            field_dict["url_paths"] = url_paths
        if cookie_patterns is not UNSET:
            field_dict["cookie_patterns"] = cookie_patterns
        if status_code_hints is not UNSET:
            field_dict["status_code_hints"] = status_code_hints

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.product_signature_model_header_patterns import ProductSignatureModelHeaderPatterns
        from ..models.product_signature_model_status_code_hints import ProductSignatureModelStatusCodeHints

        d = dict(src_dict)
        name = d.pop("name")

        _header_patterns = d.pop("header_patterns", UNSET)
        header_patterns: ProductSignatureModelHeaderPatterns | Unset
        if isinstance(_header_patterns, Unset):
            header_patterns = UNSET
        else:
            header_patterns = ProductSignatureModelHeaderPatterns.from_dict(_header_patterns)

        body_patterns = cast(list[str], d.pop("body_patterns", UNSET))

        url_paths = cast(list[str], d.pop("url_paths", UNSET))

        cookie_patterns = cast(list[str], d.pop("cookie_patterns", UNSET))

        _status_code_hints = d.pop("status_code_hints", UNSET)
        status_code_hints: ProductSignatureModelStatusCodeHints | Unset
        if isinstance(_status_code_hints, Unset):
            status_code_hints = UNSET
        else:
            status_code_hints = ProductSignatureModelStatusCodeHints.from_dict(_status_code_hints)

        product_signature_model = cls(
            name=name,
            header_patterns=header_patterns,
            body_patterns=body_patterns,
            url_paths=url_paths,
            cookie_patterns=cookie_patterns,
            status_code_hints=status_code_hints,
        )

        product_signature_model.additional_properties = d
        return product_signature_model

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
