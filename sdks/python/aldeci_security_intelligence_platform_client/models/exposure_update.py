from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExposureUpdate")


@_attrs_define
class ExposureUpdate:
    """
    Attributes:
        status (None | str | Unset):
        risk_score (float | None | Unset):
        owner (None | str | Unset):
        remediation_plan (None | str | Unset):
    """

    status: None | str | Unset = UNSET
    risk_score: float | None | Unset = UNSET
    owner: None | str | Unset = UNSET
    remediation_plan: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        risk_score: float | None | Unset
        if isinstance(self.risk_score, Unset):
            risk_score = UNSET
        else:
            risk_score = self.risk_score

        owner: None | str | Unset
        if isinstance(self.owner, Unset):
            owner = UNSET
        else:
            owner = self.owner

        remediation_plan: None | str | Unset
        if isinstance(self.remediation_plan, Unset):
            remediation_plan = UNSET
        else:
            remediation_plan = self.remediation_plan

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if status is not UNSET:
            field_dict["status"] = status
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if owner is not UNSET:
            field_dict["owner"] = owner
        if remediation_plan is not UNSET:
            field_dict["remediation_plan"] = remediation_plan

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_risk_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        risk_score = _parse_risk_score(d.pop("risk_score", UNSET))

        def _parse_owner(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner = _parse_owner(d.pop("owner", UNSET))

        def _parse_remediation_plan(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        remediation_plan = _parse_remediation_plan(d.pop("remediation_plan", UNSET))

        exposure_update = cls(
            status=status,
            risk_score=risk_score,
            owner=owner,
            remediation_plan=remediation_plan,
        )

        exposure_update.additional_properties = d
        return exposure_update

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
