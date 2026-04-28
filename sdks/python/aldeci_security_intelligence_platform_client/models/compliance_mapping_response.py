from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.compliance_mapping_response_controls_affected_item import (
        ComplianceMappingResponseControlsAffectedItem,
    )


T = TypeVar("T", bound="ComplianceMappingResponse")


@_attrs_define
class ComplianceMappingResponse:
    """Compliance mapping result.

    Attributes:
        framework (str):
        controls_mapped (int | Unset):  Default: 0.
        controls_affected (list[ComplianceMappingResponseControlsAffectedItem] | Unset):
        gap_score (float | None | Unset):
        remediation_priority (list[str] | Unset):
        status (None | str | Unset):
        message (None | str | Unset):
    """

    framework: str
    controls_mapped: int | Unset = 0
    controls_affected: list[ComplianceMappingResponseControlsAffectedItem] | Unset = UNSET
    gap_score: float | None | Unset = UNSET
    remediation_priority: list[str] | Unset = UNSET
    status: None | str | Unset = UNSET
    message: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework

        controls_mapped = self.controls_mapped

        controls_affected: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.controls_affected, Unset):
            controls_affected = []
            for controls_affected_item_data in self.controls_affected:
                controls_affected_item = controls_affected_item_data.to_dict()
                controls_affected.append(controls_affected_item)

        gap_score: float | None | Unset
        if isinstance(self.gap_score, Unset):
            gap_score = UNSET
        else:
            gap_score = self.gap_score

        remediation_priority: list[str] | Unset = UNSET
        if not isinstance(self.remediation_priority, Unset):
            remediation_priority = self.remediation_priority

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        message: None | str | Unset
        if isinstance(self.message, Unset):
            message = UNSET
        else:
            message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
            }
        )
        if controls_mapped is not UNSET:
            field_dict["controls_mapped"] = controls_mapped
        if controls_affected is not UNSET:
            field_dict["controls_affected"] = controls_affected
        if gap_score is not UNSET:
            field_dict["gap_score"] = gap_score
        if remediation_priority is not UNSET:
            field_dict["remediation_priority"] = remediation_priority
        if status is not UNSET:
            field_dict["status"] = status
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compliance_mapping_response_controls_affected_item import (
            ComplianceMappingResponseControlsAffectedItem,
        )

        d = dict(src_dict)
        framework = d.pop("framework")

        controls_mapped = d.pop("controls_mapped", UNSET)

        _controls_affected = d.pop("controls_affected", UNSET)
        controls_affected: list[ComplianceMappingResponseControlsAffectedItem] | Unset = UNSET
        if _controls_affected is not UNSET:
            controls_affected = []
            for controls_affected_item_data in _controls_affected:
                controls_affected_item = ComplianceMappingResponseControlsAffectedItem.from_dict(
                    controls_affected_item_data
                )

                controls_affected.append(controls_affected_item)

        def _parse_gap_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        gap_score = _parse_gap_score(d.pop("gap_score", UNSET))

        remediation_priority = cast(list[str], d.pop("remediation_priority", UNSET))

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        message = _parse_message(d.pop("message", UNSET))

        compliance_mapping_response = cls(
            framework=framework,
            controls_mapped=controls_mapped,
            controls_affected=controls_affected,
            gap_score=gap_score,
            remediation_priority=remediation_priority,
            status=status,
            message=message,
        )

        compliance_mapping_response.additional_properties = d
        return compliance_mapping_response

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
