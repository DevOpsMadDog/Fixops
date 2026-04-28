from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CausalAnalysisRequest")


@_attrs_define
class CausalAnalysisRequest:
    """Request for causal analysis of a vulnerability.

    Attributes:
        has_exploit (bool | Unset): Whether an exploit is available Default: False.
        is_reachable (bool | Unset): Whether vulnerable code is reachable Default: True.
        is_internet_facing (bool | Unset): Whether exposed to internet Default: False.
        has_waf (bool | Unset): Whether WAF is enabled Default: False.
        is_patched (bool | Unset): Whether vulnerability is patched Default: False.
        has_auth (bool | Unset): Whether authentication is required Default: True.
    """

    has_exploit: bool | Unset = False
    is_reachable: bool | Unset = True
    is_internet_facing: bool | Unset = False
    has_waf: bool | Unset = False
    is_patched: bool | Unset = False
    has_auth: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        has_exploit = self.has_exploit

        is_reachable = self.is_reachable

        is_internet_facing = self.is_internet_facing

        has_waf = self.has_waf

        is_patched = self.is_patched

        has_auth = self.has_auth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if has_exploit is not UNSET:
            field_dict["has_exploit"] = has_exploit
        if is_reachable is not UNSET:
            field_dict["is_reachable"] = is_reachable
        if is_internet_facing is not UNSET:
            field_dict["is_internet_facing"] = is_internet_facing
        if has_waf is not UNSET:
            field_dict["has_waf"] = has_waf
        if is_patched is not UNSET:
            field_dict["is_patched"] = is_patched
        if has_auth is not UNSET:
            field_dict["has_auth"] = has_auth

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        has_exploit = d.pop("has_exploit", UNSET)

        is_reachable = d.pop("is_reachable", UNSET)

        is_internet_facing = d.pop("is_internet_facing", UNSET)

        has_waf = d.pop("has_waf", UNSET)

        is_patched = d.pop("is_patched", UNSET)

        has_auth = d.pop("has_auth", UNSET)

        causal_analysis_request = cls(
            has_exploit=has_exploit,
            is_reachable=is_reachable,
            is_internet_facing=is_internet_facing,
            has_waf=has_waf,
            is_patched=is_patched,
            has_auth=has_auth,
        )

        causal_analysis_request.additional_properties = d
        return causal_analysis_request

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
