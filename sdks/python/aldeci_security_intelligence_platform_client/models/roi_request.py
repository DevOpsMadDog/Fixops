from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ROIRequest")


@_attrs_define
class ROIRequest:
    """Request body for ROI calculation.

    Attributes:
        program_cost_usd (float): Total annual program cost in USD
        breaches_prevented (float): Estimated breaches prevented
        tool_cost_usd (float | Unset):  Default: 0.0.
        staff_cost_usd (float | Unset):  Default: 0.0.
        training_cost_usd (float | Unset):  Default: 0.0.
        industry (str | Unset): Industry vertical for breach cost lookup Default: 'global'.
    """

    program_cost_usd: float
    breaches_prevented: float
    tool_cost_usd: float | Unset = 0.0
    staff_cost_usd: float | Unset = 0.0
    training_cost_usd: float | Unset = 0.0
    industry: str | Unset = "global"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        program_cost_usd = self.program_cost_usd

        breaches_prevented = self.breaches_prevented

        tool_cost_usd = self.tool_cost_usd

        staff_cost_usd = self.staff_cost_usd

        training_cost_usd = self.training_cost_usd

        industry = self.industry

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "program_cost_usd": program_cost_usd,
                "breaches_prevented": breaches_prevented,
            }
        )
        if tool_cost_usd is not UNSET:
            field_dict["tool_cost_usd"] = tool_cost_usd
        if staff_cost_usd is not UNSET:
            field_dict["staff_cost_usd"] = staff_cost_usd
        if training_cost_usd is not UNSET:
            field_dict["training_cost_usd"] = training_cost_usd
        if industry is not UNSET:
            field_dict["industry"] = industry

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        program_cost_usd = d.pop("program_cost_usd")

        breaches_prevented = d.pop("breaches_prevented")

        tool_cost_usd = d.pop("tool_cost_usd", UNSET)

        staff_cost_usd = d.pop("staff_cost_usd", UNSET)

        training_cost_usd = d.pop("training_cost_usd", UNSET)

        industry = d.pop("industry", UNSET)

        roi_request = cls(
            program_cost_usd=program_cost_usd,
            breaches_prevented=breaches_prevented,
            tool_cost_usd=tool_cost_usd,
            staff_cost_usd=staff_cost_usd,
            training_cost_usd=training_cost_usd,
            industry=industry,
        )

        roi_request.additional_properties = d
        return roi_request

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
