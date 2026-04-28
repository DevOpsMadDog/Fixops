from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.posture_component_details import PostureComponentDetails


T = TypeVar("T", bound="PostureComponent")


@_attrs_define
class PostureComponent:
    """A single component of the overall posture score.

    Attributes:
        name (str): Component identifier (e.g. 'vulnerability_density')
        score (float): Component score 0-100
        weight (float): Fractional weight in overall score
        details (PostureComponentDetails | Unset): Supporting metrics
    """

    name: str
    score: float
    weight: float
    details: PostureComponentDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        score = self.score

        weight = self.weight

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "score": score,
                "weight": weight,
            }
        )
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.posture_component_details import PostureComponentDetails

        d = dict(src_dict)
        name = d.pop("name")

        score = d.pop("score")

        weight = d.pop("weight")

        _details = d.pop("details", UNSET)
        details: PostureComponentDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = PostureComponentDetails.from_dict(_details)

        posture_component = cls(
            name=name,
            score=score,
            weight=weight,
            details=details,
        )

        posture_component.additional_properties = d
        return posture_component

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
