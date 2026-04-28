from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WorkloadCreateReq")


@_attrs_define
class WorkloadCreateReq:
    """
    Attributes:
        org_id (str):
        workload_name (str):
        workload_type (str | Unset):  Default: 'vm'.
        cloud_provider (str | Unset):  Default: 'aws'.
        region (None | str | Unset):
        account_id (None | str | Unset):
        risk_score (float | Unset):  Default: 50.0.
        risk_level (str | Unset):  Default: 'medium'.
        last_assessed (None | str | Unset):
    """

    org_id: str
    workload_name: str
    workload_type: str | Unset = "vm"
    cloud_provider: str | Unset = "aws"
    region: None | str | Unset = UNSET
    account_id: None | str | Unset = UNSET
    risk_score: float | Unset = 50.0
    risk_level: str | Unset = "medium"
    last_assessed: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        workload_name = self.workload_name

        workload_type = self.workload_type

        cloud_provider = self.cloud_provider

        region: None | str | Unset
        if isinstance(self.region, Unset):
            region = UNSET
        else:
            region = self.region

        account_id: None | str | Unset
        if isinstance(self.account_id, Unset):
            account_id = UNSET
        else:
            account_id = self.account_id

        risk_score = self.risk_score

        risk_level = self.risk_level

        last_assessed: None | str | Unset
        if isinstance(self.last_assessed, Unset):
            last_assessed = UNSET
        else:
            last_assessed = self.last_assessed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "workload_name": workload_name,
            }
        )
        if workload_type is not UNSET:
            field_dict["workload_type"] = workload_type
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if region is not UNSET:
            field_dict["region"] = region
        if account_id is not UNSET:
            field_dict["account_id"] = account_id
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if last_assessed is not UNSET:
            field_dict["last_assessed"] = last_assessed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        workload_name = d.pop("workload_name")

        workload_type = d.pop("workload_type", UNSET)

        cloud_provider = d.pop("cloud_provider", UNSET)

        def _parse_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        region = _parse_region(d.pop("region", UNSET))

        def _parse_account_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        account_id = _parse_account_id(d.pop("account_id", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        def _parse_last_assessed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_assessed = _parse_last_assessed(d.pop("last_assessed", UNSET))

        workload_create_req = cls(
            org_id=org_id,
            workload_name=workload_name,
            workload_type=workload_type,
            cloud_provider=cloud_provider,
            region=region,
            account_id=account_id,
            risk_score=risk_score,
            risk_level=risk_level,
            last_assessed=last_assessed,
        )

        workload_create_req.additional_properties = d
        return workload_create_req

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
