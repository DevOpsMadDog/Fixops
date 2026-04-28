from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.zero_trust_dimension import ZeroTrustDimension


T = TypeVar("T", bound="ZeroTrustScore")


@_attrs_define
class ZeroTrustScore:
    """
    Attributes:
        org_id (str):
        segment (str):
        overall_score (float):
        grade (str):
        id (str | Unset):
        dimensions (list[ZeroTrustDimension] | Unset):
        recommendations (list[str] | Unset):
        computed_at (datetime.datetime | Unset):
    """

    org_id: str
    segment: str
    overall_score: float
    grade: str
    id: str | Unset = UNSET
    dimensions: list[ZeroTrustDimension] | Unset = UNSET
    recommendations: list[str] | Unset = UNSET
    computed_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        segment = self.segment

        overall_score = self.overall_score

        grade = self.grade

        id = self.id

        dimensions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.dimensions, Unset):
            dimensions = []
            for dimensions_item_data in self.dimensions:
                dimensions_item = dimensions_item_data.to_dict()
                dimensions.append(dimensions_item)

        recommendations: list[str] | Unset = UNSET
        if not isinstance(self.recommendations, Unset):
            recommendations = self.recommendations

        computed_at: str | Unset = UNSET
        if not isinstance(self.computed_at, Unset):
            computed_at = self.computed_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "segment": segment,
                "overall_score": overall_score,
                "grade": grade,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if dimensions is not UNSET:
            field_dict["dimensions"] = dimensions
        if recommendations is not UNSET:
            field_dict["recommendations"] = recommendations
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.zero_trust_dimension import ZeroTrustDimension

        d = dict(src_dict)
        org_id = d.pop("org_id")

        segment = d.pop("segment")

        overall_score = d.pop("overall_score")

        grade = d.pop("grade")

        id = d.pop("id", UNSET)

        _dimensions = d.pop("dimensions", UNSET)
        dimensions: list[ZeroTrustDimension] | Unset = UNSET
        if _dimensions is not UNSET:
            dimensions = []
            for dimensions_item_data in _dimensions:
                dimensions_item = ZeroTrustDimension.from_dict(dimensions_item_data)

                dimensions.append(dimensions_item)

        recommendations = cast(list[str], d.pop("recommendations", UNSET))

        _computed_at = d.pop("computed_at", UNSET)
        computed_at: datetime.datetime | Unset
        if isinstance(_computed_at, Unset):
            computed_at = UNSET
        else:
            computed_at = isoparse(_computed_at)

        zero_trust_score = cls(
            org_id=org_id,
            segment=segment,
            overall_score=overall_score,
            grade=grade,
            id=id,
            dimensions=dimensions,
            recommendations=recommendations,
            computed_at=computed_at,
        )

        zero_trust_score.additional_properties = d
        return zero_trust_score

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
