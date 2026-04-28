from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CurrentStageResponse")


@_attrs_define
class CurrentStageResponse:
    """Current stage of a finding.

    Attributes:
        finding_id (str):
        stage (None | str):
    """

    finding_id: str
    stage: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        stage: None | str
        stage = self.stage

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "stage": stage,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        def _parse_stage(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        stage = _parse_stage(d.pop("stage"))

        current_stage_response = cls(
            finding_id=finding_id,
            stage=stage,
        )

        current_stage_response.additional_properties = d
        return current_stage_response

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
