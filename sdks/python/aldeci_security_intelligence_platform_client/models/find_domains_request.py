from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FindDomainsRequest")


@_attrs_define
class FindDomainsRequest:
    """
    Attributes:
        parent_domain (str): Parent-org apex domain, e.g. acmecorp.com
        org_id (str | Unset): Organisation ID Default: 'default'.
        seed_patterns (list[str] | Unset): Optional seed substrings to boost confidence (e.g. subsidiary names)
    """

    parent_domain: str
    org_id: str | Unset = "default"
    seed_patterns: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        parent_domain = self.parent_domain

        org_id = self.org_id

        seed_patterns: list[str] | Unset = UNSET
        if not isinstance(self.seed_patterns, Unset):
            seed_patterns = self.seed_patterns

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "parent_domain": parent_domain,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if seed_patterns is not UNSET:
            field_dict["seed_patterns"] = seed_patterns

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        parent_domain = d.pop("parent_domain")

        org_id = d.pop("org_id", UNSET)

        seed_patterns = cast(list[str], d.pop("seed_patterns", UNSET))

        find_domains_request = cls(
            parent_domain=parent_domain,
            org_id=org_id,
            seed_patterns=seed_patterns,
        )

        find_domains_request.additional_properties = d
        return find_domains_request

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
