from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ScoreOverrideCreate")


@_attrs_define
class ScoreOverrideCreate:
    """
    Attributes:
        override_reason (str):
        override_score (float):
        override_tier (str):
        overridden_by (str):
    """

    override_reason: str
    override_score: float
    override_tier: str
    overridden_by: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        override_reason = self.override_reason

        override_score = self.override_score

        override_tier = self.override_tier

        overridden_by = self.overridden_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "override_reason": override_reason,
                "override_score": override_score,
                "override_tier": override_tier,
                "overridden_by": overridden_by,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        override_reason = d.pop("override_reason")

        override_score = d.pop("override_score")

        override_tier = d.pop("override_tier")

        overridden_by = d.pop("overridden_by")

        score_override_create = cls(
            override_reason=override_reason,
            override_score=override_score,
            override_tier=override_tier,
            overridden_by=overridden_by,
        )

        score_override_create.additional_properties = d
        return score_override_create

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
