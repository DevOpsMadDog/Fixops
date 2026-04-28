from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SubmitReputationRequest")


@_attrs_define
class SubmitReputationRequest:
    """
    Attributes:
        ip (str): IP address
        org_id (str | Unset): Organisation identifier Default: 'default'.
        reputation_score (int | Unset): Reputation score 0-100 (lower = worse reputation) Default: 50.
        categories (list[str] | Unset): Threat categories: spam, botnet, proxy, tor, scanner, malware
        source (str | Unset): Data source / feed name Default: ''.
    """

    ip: str
    org_id: str | Unset = "default"
    reputation_score: int | Unset = 50
    categories: list[str] | Unset = UNSET
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ip = self.ip

        org_id = self.org_id

        reputation_score = self.reputation_score

        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = self.categories

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ip": ip,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if reputation_score is not UNSET:
            field_dict["reputation_score"] = reputation_score
        if categories is not UNSET:
            field_dict["categories"] = categories
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ip = d.pop("ip")

        org_id = d.pop("org_id", UNSET)

        reputation_score = d.pop("reputation_score", UNSET)

        categories = cast(list[str], d.pop("categories", UNSET))

        source = d.pop("source", UNSET)

        submit_reputation_request = cls(
            ip=ip,
            org_id=org_id,
            reputation_score=reputation_score,
            categories=categories,
            source=source,
        )

        submit_reputation_request.additional_properties = d
        return submit_reputation_request

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
