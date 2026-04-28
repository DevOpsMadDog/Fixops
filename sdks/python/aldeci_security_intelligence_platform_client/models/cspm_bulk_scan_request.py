from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CSPMBulkScanRequest")


@_attrs_define
class CSPMBulkScanRequest:
    """
    Attributes:
        tenants (list[str]):
        provider (str | Unset):  Default: 'aws'.
        account_id (str | Unset):  Default: '000000000000'.
        localstack_endpoint (str | Unset):  Default: 'http://localhost:4566'.
        iac_dir (None | str | Unset):
        run_prowler (bool | Unset):  Default: True.
        run_checkov (bool | Unset):  Default: True.
        run_cloudsploit (bool | Unset):  Default: True.
        run_agentless (bool | Unset):  Default: True.
        run_trivy (bool | Unset):  Default: True.
    """

    tenants: list[str]
    provider: str | Unset = "aws"
    account_id: str | Unset = "000000000000"
    localstack_endpoint: str | Unset = "http://localhost:4566"
    iac_dir: None | str | Unset = UNSET
    run_prowler: bool | Unset = True
    run_checkov: bool | Unset = True
    run_cloudsploit: bool | Unset = True
    run_agentless: bool | Unset = True
    run_trivy: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tenants = self.tenants

        provider = self.provider

        account_id = self.account_id

        localstack_endpoint = self.localstack_endpoint

        iac_dir: None | str | Unset
        if isinstance(self.iac_dir, Unset):
            iac_dir = UNSET
        else:
            iac_dir = self.iac_dir

        run_prowler = self.run_prowler

        run_checkov = self.run_checkov

        run_cloudsploit = self.run_cloudsploit

        run_agentless = self.run_agentless

        run_trivy = self.run_trivy

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tenants": tenants,
            }
        )
        if provider is not UNSET:
            field_dict["provider"] = provider
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if localstack_endpoint is not UNSET:
            field_dict["localstack_endpoint"] = localstack_endpoint
        if iac_dir is not UNSET:
            field_dict["iac_dir"] = iac_dir
        if run_prowler is not UNSET:
            field_dict["run_prowler"] = run_prowler
        if run_checkov is not UNSET:
            field_dict["run_checkov"] = run_checkov
        if run_cloudsploit is not UNSET:
            field_dict["run_cloudsploit"] = run_cloudsploit
        if run_agentless is not UNSET:
            field_dict["run_agentless"] = run_agentless
        if run_trivy is not UNSET:
            field_dict["run_trivy"] = run_trivy

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tenants = cast(list[str], d.pop("tenants"))

        provider = d.pop("provider", UNSET)

        account_id = d.pop("account_id", UNSET)

        localstack_endpoint = d.pop("localstack_endpoint", UNSET)

        def _parse_iac_dir(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        iac_dir = _parse_iac_dir(d.pop("iac_dir", UNSET))

        run_prowler = d.pop("run_prowler", UNSET)

        run_checkov = d.pop("run_checkov", UNSET)

        run_cloudsploit = d.pop("run_cloudsploit", UNSET)

        run_agentless = d.pop("run_agentless", UNSET)

        run_trivy = d.pop("run_trivy", UNSET)

        cspm_bulk_scan_request = cls(
            tenants=tenants,
            provider=provider,
            account_id=account_id,
            localstack_endpoint=localstack_endpoint,
            iac_dir=iac_dir,
            run_prowler=run_prowler,
            run_checkov=run_checkov,
            run_cloudsploit=run_cloudsploit,
            run_agentless=run_agentless,
            run_trivy=run_trivy,
        )

        cspm_bulk_scan_request.additional_properties = d
        return cspm_bulk_scan_request

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
