from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PoCRequest")


@_attrs_define
class PoCRequest:
    """Request model for PoC verification.

    Attributes:
        code (str): PoC script code
        language (str | Unset): Script language: python, bash, nodejs, curl, go Default: 'python'.
        cve_id (str | Unset): CVE identifier Default: ''.
        target_url (str | Unset): Target URL for network-based PoCs Default: ''.
        expected_indicators (list[str] | Unset): Strings expected in output if exploitable
        timeout_seconds (int | Unset):  Default: 30.
        requires_network (bool | Unset):  Default: False.
        finding_id (str | Unset):  Default: ''.
    """

    code: str
    language: str | Unset = "python"
    cve_id: str | Unset = ""
    target_url: str | Unset = ""
    expected_indicators: list[str] | Unset = UNSET
    timeout_seconds: int | Unset = 30
    requires_network: bool | Unset = False
    finding_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        code = self.code

        language = self.language

        cve_id = self.cve_id

        target_url = self.target_url

        expected_indicators: list[str] | Unset = UNSET
        if not isinstance(self.expected_indicators, Unset):
            expected_indicators = self.expected_indicators

        timeout_seconds = self.timeout_seconds

        requires_network = self.requires_network

        finding_id = self.finding_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "code": code,
            }
        )
        if language is not UNSET:
            field_dict["language"] = language
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if target_url is not UNSET:
            field_dict["target_url"] = target_url
        if expected_indicators is not UNSET:
            field_dict["expected_indicators"] = expected_indicators
        if timeout_seconds is not UNSET:
            field_dict["timeout_seconds"] = timeout_seconds
        if requires_network is not UNSET:
            field_dict["requires_network"] = requires_network
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        code = d.pop("code")

        language = d.pop("language", UNSET)

        cve_id = d.pop("cve_id", UNSET)

        target_url = d.pop("target_url", UNSET)

        expected_indicators = cast(list[str], d.pop("expected_indicators", UNSET))

        timeout_seconds = d.pop("timeout_seconds", UNSET)

        requires_network = d.pop("requires_network", UNSET)

        finding_id = d.pop("finding_id", UNSET)

        po_c_request = cls(
            code=code,
            language=language,
            cve_id=cve_id,
            target_url=target_url,
            expected_indicators=expected_indicators,
            timeout_seconds=timeout_seconds,
            requires_network=requires_network,
            finding_id=finding_id,
        )

        po_c_request.additional_properties = d
        return po_c_request

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
