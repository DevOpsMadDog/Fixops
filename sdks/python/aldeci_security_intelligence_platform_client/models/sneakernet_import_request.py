from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SneakernetImportRequest")


@_attrs_define
class SneakernetImportRequest:
    """Request body for importing a sneakernet update package.

    Attributes:
        package_path (str): Absolute path to the .snk package file on the server
        encryption_key_hex (str): 64-hex-char AES-256 key that was used when exporting
        extract_dir (None | str | Unset): Override extraction directory
    """

    package_path: str
    encryption_key_hex: str
    extract_dir: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_path = self.package_path

        encryption_key_hex = self.encryption_key_hex

        extract_dir: None | str | Unset
        if isinstance(self.extract_dir, Unset):
            extract_dir = UNSET
        else:
            extract_dir = self.extract_dir

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_path": package_path,
                "encryption_key_hex": encryption_key_hex,
            }
        )
        if extract_dir is not UNSET:
            field_dict["extract_dir"] = extract_dir

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_path = d.pop("package_path")

        encryption_key_hex = d.pop("encryption_key_hex")

        def _parse_extract_dir(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        extract_dir = _parse_extract_dir(d.pop("extract_dir", UNSET))

        sneakernet_import_request = cls(
            package_path=package_path,
            encryption_key_hex=encryption_key_hex,
            extract_dir=extract_dir,
        )

        sneakernet_import_request.additional_properties = d
        return sneakernet_import_request

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
