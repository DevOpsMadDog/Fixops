from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.remediation_action import RemediationAction
from ..types import UNSET, Unset

T = TypeVar("T", bound="RemediationRecommendation")


@_attrs_define
class RemediationRecommendation:
    """Recommended remediation for a vulnerability.

    Attributes:
        action (RemediationAction): Type of recommended remediation action.
        description (str):
        affected_version (None | str | Unset):
        fixed_version (None | str | Unset):
        workaround_detail (None | str | Unset):
        accept_risk_template (None | str | Unset):
        effort_hours (float | None | Unset):
        confidence (float | Unset):  Default: 0.8.
    """

    action: RemediationAction
    description: str
    affected_version: None | str | Unset = UNSET
    fixed_version: None | str | Unset = UNSET
    workaround_detail: None | str | Unset = UNSET
    accept_risk_template: None | str | Unset = UNSET
    effort_hours: float | None | Unset = UNSET
    confidence: float | Unset = 0.8
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action = self.action.value

        description = self.description

        affected_version: None | str | Unset
        if isinstance(self.affected_version, Unset):
            affected_version = UNSET
        else:
            affected_version = self.affected_version

        fixed_version: None | str | Unset
        if isinstance(self.fixed_version, Unset):
            fixed_version = UNSET
        else:
            fixed_version = self.fixed_version

        workaround_detail: None | str | Unset
        if isinstance(self.workaround_detail, Unset):
            workaround_detail = UNSET
        else:
            workaround_detail = self.workaround_detail

        accept_risk_template: None | str | Unset
        if isinstance(self.accept_risk_template, Unset):
            accept_risk_template = UNSET
        else:
            accept_risk_template = self.accept_risk_template

        effort_hours: float | None | Unset
        if isinstance(self.effort_hours, Unset):
            effort_hours = UNSET
        else:
            effort_hours = self.effort_hours

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action": action,
                "description": description,
            }
        )
        if affected_version is not UNSET:
            field_dict["affected_version"] = affected_version
        if fixed_version is not UNSET:
            field_dict["fixed_version"] = fixed_version
        if workaround_detail is not UNSET:
            field_dict["workaround_detail"] = workaround_detail
        if accept_risk_template is not UNSET:
            field_dict["accept_risk_template"] = accept_risk_template
        if effort_hours is not UNSET:
            field_dict["effort_hours"] = effort_hours
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = RemediationAction(d.pop("action"))

        description = d.pop("description")

        def _parse_affected_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        affected_version = _parse_affected_version(d.pop("affected_version", UNSET))

        def _parse_fixed_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        fixed_version = _parse_fixed_version(d.pop("fixed_version", UNSET))

        def _parse_workaround_detail(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        workaround_detail = _parse_workaround_detail(d.pop("workaround_detail", UNSET))

        def _parse_accept_risk_template(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        accept_risk_template = _parse_accept_risk_template(d.pop("accept_risk_template", UNSET))

        def _parse_effort_hours(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        effort_hours = _parse_effort_hours(d.pop("effort_hours", UNSET))

        confidence = d.pop("confidence", UNSET)

        remediation_recommendation = cls(
            action=action,
            description=description,
            affected_version=affected_version,
            fixed_version=fixed_version,
            workaround_detail=workaround_detail,
            accept_risk_template=accept_risk_template,
            effort_hours=effort_hours,
            confidence=confidence,
        )

        remediation_recommendation.additional_properties = d
        return remediation_recommendation

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
