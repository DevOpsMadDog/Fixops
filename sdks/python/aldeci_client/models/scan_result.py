from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.vulnerability_item import VulnerabilityItem


T = TypeVar("T", bound="ScanResult")


@_attrs_define
class ScanResult:
    """
    Attributes:
        file_path (str):
        total (int):
        vulnerabilities (list[VulnerabilityItem]):
    """

    file_path: str
    total: int
    vulnerabilities: list[VulnerabilityItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        file_path = self.file_path

        total = self.total

        vulnerabilities = []
        for vulnerabilities_item_data in self.vulnerabilities:
            vulnerabilities_item = vulnerabilities_item_data.to_dict()
            vulnerabilities.append(vulnerabilities_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "file_path": file_path,
                "total": total,
                "vulnerabilities": vulnerabilities,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vulnerability_item import VulnerabilityItem

        d = dict(src_dict)
        file_path = d.pop("file_path")

        total = d.pop("total")

        vulnerabilities = []
        _vulnerabilities = d.pop("vulnerabilities")
        for vulnerabilities_item_data in _vulnerabilities:
            vulnerabilities_item = VulnerabilityItem.from_dict(vulnerabilities_item_data)

            vulnerabilities.append(vulnerabilities_item)

        scan_result = cls(
            file_path=file_path,
            total=total,
            vulnerabilities=vulnerabilities,
        )

        scan_result.additional_properties = d
        return scan_result

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
