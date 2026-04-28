from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttackChainRequest")


@_attrs_define
class AttackChainRequest:
    """Request for attack chain prediction.

    Attributes:
        cve_id (str): CVE identifier
        cvss_score (float | Unset): CVSS score (0-10) Default: 7.5.
        has_exploit (bool | Unset): Whether an exploit is available Default: False.
        is_network_exposed (bool | Unset): Whether vulnerability is network-accessible Default: True.
    """

    cve_id: str
    cvss_score: float | Unset = 7.5
    has_exploit: bool | Unset = False
    is_network_exposed: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id = self.cve_id

        cvss_score = self.cvss_score

        has_exploit = self.has_exploit

        is_network_exposed = self.is_network_exposed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cve_id": cve_id,
            }
        )
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if has_exploit is not UNSET:
            field_dict["has_exploit"] = has_exploit
        if is_network_exposed is not UNSET:
            field_dict["is_network_exposed"] = is_network_exposed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_id = d.pop("cve_id")

        cvss_score = d.pop("cvss_score", UNSET)

        has_exploit = d.pop("has_exploit", UNSET)

        is_network_exposed = d.pop("is_network_exposed", UNSET)

        attack_chain_request = cls(
            cve_id=cve_id,
            cvss_score=cvss_score,
            has_exploit=has_exploit,
            is_network_exposed=is_network_exposed,
        )

        attack_chain_request.additional_properties = d
        return attack_chain_request

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
