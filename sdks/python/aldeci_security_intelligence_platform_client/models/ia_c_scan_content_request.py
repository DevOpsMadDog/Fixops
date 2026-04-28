from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.ia_c_provider import IaCProvider
from ..types import UNSET, Unset

T = TypeVar("T", bound="IaCScanContentRequest")


@_attrs_define
class IaCScanContentRequest:
    """Request model for scanning IaC content.

    Attributes:
        content (str): IaC file content to scan
        filename (str): Filename (used for provider detection)
        provider (IaCProvider | None | Unset): IaC provider type (auto-detected if not specified)
        scanner (None | str | Unset): Scanner to use: 'checkov' or 'tfsec' (auto-selected if not specified)
    """

    content: str
    filename: str
    provider: IaCProvider | None | Unset = UNSET
    scanner: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        content = self.content

        filename = self.filename

        provider: None | str | Unset
        if isinstance(self.provider, Unset):
            provider = UNSET
        elif isinstance(self.provider, IaCProvider):
            provider = self.provider.value
        else:
            provider = self.provider

        scanner: None | str | Unset
        if isinstance(self.scanner, Unset):
            scanner = UNSET
        else:
            scanner = self.scanner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "content": content,
                "filename": filename,
            }
        )
        if provider is not UNSET:
            field_dict["provider"] = provider
        if scanner is not UNSET:
            field_dict["scanner"] = scanner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        content = d.pop("content")

        filename = d.pop("filename")

        def _parse_provider(data: object) -> IaCProvider | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                provider_type_0 = IaCProvider(data)

                return provider_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(IaCProvider | None | Unset, data)

        provider = _parse_provider(d.pop("provider", UNSET))

        def _parse_scanner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanner = _parse_scanner(d.pop("scanner", UNSET))

        ia_c_scan_content_request = cls(
            content=content,
            filename=filename,
            provider=provider,
            scanner=scanner,
        )

        ia_c_scan_content_request.additional_properties = d
        return ia_c_scan_content_request

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
