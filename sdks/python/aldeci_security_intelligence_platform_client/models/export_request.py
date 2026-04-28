from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExportRequest")


@_attrs_define
class ExportRequest:
    """Request body for POST /evidence/export — signed compliance bundle.

    Attributes:
        framework (str | Unset): Compliance framework for control mapping Default: 'SOC2'.
        app_id (str | Unset): Optional APP_ID scope Default: ''.
        period_days (int | Unset): Assessment period in days Default: 90.
        include_evidence (bool | Unset): Include evidence items per control Default: True.
        sign (bool | Unset): Sign the bundle with RSA-SHA256 Default: True.
    """

    framework: str | Unset = "SOC2"
    app_id: str | Unset = ""
    period_days: int | Unset = 90
    include_evidence: bool | Unset = True
    sign: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        app_id = self.app_id

        period_days = self.period_days

        include_evidence = self.include_evidence

        sign = self.sign

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if framework is not UNSET:
            field_dict["framework"] = framework
        if app_id is not UNSET:
            field_dict["app_id"] = app_id
        if period_days is not UNSET:
            field_dict["period_days"] = period_days
        if include_evidence is not UNSET:
            field_dict["include_evidence"] = include_evidence
        if sign is not UNSET:
            field_dict["sign"] = sign

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = d.pop("framework", UNSET)

        app_id = d.pop("app_id", UNSET)

        period_days = d.pop("period_days", UNSET)

        include_evidence = d.pop("include_evidence", UNSET)

        sign = d.pop("sign", UNSET)

        export_request = cls(
            framework=framework,
            app_id=app_id,
            period_days=period_days,
            include_evidence=include_evidence,
            sign=sign,
        )

        export_request.additional_properties = d
        return export_request

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
