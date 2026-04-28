from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegulationCreate")


@_attrs_define
class RegulationCreate:
    """
    Attributes:
        name (str):
        jurisdiction (str | Unset):  Default: ''.
        category (str | Unset):  Default: 'cybersecurity'.
        version (str | Unset):  Default: ''.
        effective_date (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'enacted'.
        url (str | Unset):  Default: ''.
    """

    name: str
    jurisdiction: str | Unset = ""
    category: str | Unset = "cybersecurity"
    version: str | Unset = ""
    effective_date: str | Unset = ""
    status: str | Unset = "enacted"
    url: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        jurisdiction = self.jurisdiction

        category = self.category

        version = self.version

        effective_date = self.effective_date

        status = self.status

        url = self.url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if jurisdiction is not UNSET:
            field_dict["jurisdiction"] = jurisdiction
        if category is not UNSET:
            field_dict["category"] = category
        if version is not UNSET:
            field_dict["version"] = version
        if effective_date is not UNSET:
            field_dict["effective_date"] = effective_date
        if status is not UNSET:
            field_dict["status"] = status
        if url is not UNSET:
            field_dict["url"] = url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        jurisdiction = d.pop("jurisdiction", UNSET)

        category = d.pop("category", UNSET)

        version = d.pop("version", UNSET)

        effective_date = d.pop("effective_date", UNSET)

        status = d.pop("status", UNSET)

        url = d.pop("url", UNSET)

        regulation_create = cls(
            name=name,
            jurisdiction=jurisdiction,
            category=category,
            version=version,
            effective_date=effective_date,
            status=status,
            url=url,
        )

        regulation_create.additional_properties = d
        return regulation_create

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
