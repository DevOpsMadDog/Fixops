from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.posture_component import PostureComponent


T = TypeVar("T", bound="PostureScore")


@_attrs_define
class PostureScore:
    """Aggregate posture score for an organisation at a point in time.

    Attributes:
        org_id (str): Organisation identifier
        overall_score (float): Weighted aggregate score 0-100
        grade (str): Letter grade A-F
        id (str | Unset):
        components (list[PostureComponent] | Unset):
        calculated_at (str | Unset): ISO-8601 UTC timestamp
        period (str | Unset): Score period label Default: 'current'.
    """

    org_id: str
    overall_score: float
    grade: str
    id: str | Unset = UNSET
    components: list[PostureComponent] | Unset = UNSET
    calculated_at: str | Unset = UNSET
    period: str | Unset = "current"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        overall_score = self.overall_score

        grade = self.grade

        id = self.id

        components: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.components, Unset):
            components = []
            for components_item_data in self.components:
                components_item = components_item_data.to_dict()
                components.append(components_item)

        calculated_at = self.calculated_at

        period = self.period

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "overall_score": overall_score,
                "grade": grade,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if components is not UNSET:
            field_dict["components"] = components
        if calculated_at is not UNSET:
            field_dict["calculated_at"] = calculated_at
        if period is not UNSET:
            field_dict["period"] = period

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.posture_component import PostureComponent

        d = dict(src_dict)
        org_id = d.pop("org_id")

        overall_score = d.pop("overall_score")

        grade = d.pop("grade")

        id = d.pop("id", UNSET)

        _components = d.pop("components", UNSET)
        components: list[PostureComponent] | Unset = UNSET
        if _components is not UNSET:
            components = []
            for components_item_data in _components:
                components_item = PostureComponent.from_dict(components_item_data)

                components.append(components_item)

        calculated_at = d.pop("calculated_at", UNSET)

        period = d.pop("period", UNSET)

        posture_score = cls(
            org_id=org_id,
            overall_score=overall_score,
            grade=grade,
            id=id,
            components=components,
            calculated_at=calculated_at,
            period=period,
        )

        posture_score.additional_properties = d
        return posture_score

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
