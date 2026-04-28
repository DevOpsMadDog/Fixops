from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CheckCreate")


@_attrs_define
class CheckCreate:
    """
    Attributes:
        check_id (str):
        check_name (str | Unset):  Default: ''.
        benchmark (str | Unset): cis_windows_l1/cis_ubuntu/etc. Default: 'cis_windows_l1'.
        category (str | Unset): account_policy/local_policy/etc. Default: 'local_policy'.
        severity (str | Unset): critical/high/medium/low Default: 'medium'.
        status (str | Unset): passed/failed/not_applicable/error Default: 'failed'.
        actual_value (str | Unset):  Default: ''.
        expected_value (str | Unset):  Default: ''.
        remediation (str | Unset):  Default: ''.
        scanned_at (None | str | Unset):
    """

    check_id: str
    check_name: str | Unset = ""
    benchmark: str | Unset = "cis_windows_l1"
    category: str | Unset = "local_policy"
    severity: str | Unset = "medium"
    status: str | Unset = "failed"
    actual_value: str | Unset = ""
    expected_value: str | Unset = ""
    remediation: str | Unset = ""
    scanned_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        check_id = self.check_id

        check_name = self.check_name

        benchmark = self.benchmark

        category = self.category

        severity = self.severity

        status = self.status

        actual_value = self.actual_value

        expected_value = self.expected_value

        remediation = self.remediation

        scanned_at: None | str | Unset
        if isinstance(self.scanned_at, Unset):
            scanned_at = UNSET
        else:
            scanned_at = self.scanned_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "check_id": check_id,
            }
        )
        if check_name is not UNSET:
            field_dict["check_name"] = check_name
        if benchmark is not UNSET:
            field_dict["benchmark"] = benchmark
        if category is not UNSET:
            field_dict["category"] = category
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status
        if actual_value is not UNSET:
            field_dict["actual_value"] = actual_value
        if expected_value is not UNSET:
            field_dict["expected_value"] = expected_value
        if remediation is not UNSET:
            field_dict["remediation"] = remediation
        if scanned_at is not UNSET:
            field_dict["scanned_at"] = scanned_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        check_id = d.pop("check_id")

        check_name = d.pop("check_name", UNSET)

        benchmark = d.pop("benchmark", UNSET)

        category = d.pop("category", UNSET)

        severity = d.pop("severity", UNSET)

        status = d.pop("status", UNSET)

        actual_value = d.pop("actual_value", UNSET)

        expected_value = d.pop("expected_value", UNSET)

        remediation = d.pop("remediation", UNSET)

        def _parse_scanned_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scanned_at = _parse_scanned_at(d.pop("scanned_at", UNSET))

        check_create = cls(
            check_id=check_id,
            check_name=check_name,
            benchmark=benchmark,
            category=category,
            severity=severity,
            status=status,
            actual_value=actual_value,
            expected_value=expected_value,
            remediation=remediation,
            scanned_at=scanned_at,
        )

        check_create.additional_properties = d
        return check_create

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
