from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.scan_files_request_files import ScanFilesRequestFiles


T = TypeVar("T", bound="ScanFilesRequest")


@_attrs_define
class ScanFilesRequest:
    """
    Attributes:
        files (ScanFilesRequestFiles):
    """

    files: ScanFilesRequestFiles
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        files = self.files.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "files": files,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.scan_files_request_files import ScanFilesRequestFiles

        d = dict(src_dict)
        files = ScanFilesRequestFiles.from_dict(d.pop("files"))

        scan_files_request = cls(
            files=files,
        )

        scan_files_request.additional_properties = d
        return scan_files_request

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
