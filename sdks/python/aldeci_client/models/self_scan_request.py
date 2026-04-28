from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SelfScanRequest")


@_attrs_define
class SelfScanRequest:
    """
    Attributes:
        target_url (str | Unset): Base URL of ALDECI to pentest. Defaults to localhost self-test. Default:
            'http://localhost:8000'.
        campaign_type (str | Unset): OpenClaw campaign type — web_app runs OWASP Top 10 checks. Default: 'web_app'.
        operators_count (int | Unset):  Default: 3.
        run_owasp_checks (bool | Unset): When True, also runs auto_pentest OWASP Top 10 probes against the target.
            Default: True.
    """

    target_url: str | Unset = "http://localhost:8000"
    campaign_type: str | Unset = "web_app"
    operators_count: int | Unset = 3
    run_owasp_checks: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target_url = self.target_url

        campaign_type = self.campaign_type

        operators_count = self.operators_count

        run_owasp_checks = self.run_owasp_checks

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target_url is not UNSET:
            field_dict["target_url"] = target_url
        if campaign_type is not UNSET:
            field_dict["campaign_type"] = campaign_type
        if operators_count is not UNSET:
            field_dict["operators_count"] = operators_count
        if run_owasp_checks is not UNSET:
            field_dict["run_owasp_checks"] = run_owasp_checks

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target_url = d.pop("target_url", UNSET)

        campaign_type = d.pop("campaign_type", UNSET)

        operators_count = d.pop("operators_count", UNSET)

        run_owasp_checks = d.pop("run_owasp_checks", UNSET)

        self_scan_request = cls(
            target_url=target_url,
            campaign_type=campaign_type,
            operators_count=operators_count,
            run_owasp_checks=run_owasp_checks,
        )

        self_scan_request.additional_properties = d
        return self_scan_request

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
