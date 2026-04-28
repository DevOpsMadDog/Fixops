from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestJsonRequest")


@_attrs_define
class IngestJsonRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        raw_json (str): Raw Prowler JSON output
        provider (str | Unset): Cloud provider: aws/azure/gcp Default: 'aws'.
        account_id (str | Unset): Cloud account ID Default: ''.
    """

    org_id: str
    raw_json: str
    provider: str | Unset = "aws"
    account_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        raw_json = self.raw_json

        provider = self.provider

        account_id = self.account_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "raw_json": raw_json,
            }
        )
        if provider is not UNSET:
            field_dict["provider"] = provider
        if account_id is not UNSET:
            field_dict["account_id"] = account_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        raw_json = d.pop("raw_json")

        provider = d.pop("provider", UNSET)

        account_id = d.pop("account_id", UNSET)

        ingest_json_request = cls(
            org_id=org_id,
            raw_json=raw_json,
            provider=provider,
            account_id=account_id,
        )

        ingest_json_request.additional_properties = d
        return ingest_json_request

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
