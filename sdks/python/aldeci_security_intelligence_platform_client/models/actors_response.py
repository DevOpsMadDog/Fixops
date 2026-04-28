from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.threat_actor_profile import ThreatActorProfile


T = TypeVar("T", bound="ActorsResponse")


@_attrs_define
class ActorsResponse:
    """
    Attributes:
        actors (list[ThreatActorProfile]):
        total (int):
    """

    actors: list[ThreatActorProfile]
    total: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        actors = []
        for actors_item_data in self.actors:
            actors_item = actors_item_data.to_dict()
            actors.append(actors_item)

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "actors": actors,
                "total": total,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.threat_actor_profile import ThreatActorProfile

        d = dict(src_dict)
        actors = []
        _actors = d.pop("actors")
        for actors_item_data in _actors:
            actors_item = ThreatActorProfile.from_dict(actors_item_data)

            actors.append(actors_item)

        total = d.pop("total")

        actors_response = cls(
            actors=actors,
            total=total,
        )

        actors_response.additional_properties = d
        return actors_response

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
