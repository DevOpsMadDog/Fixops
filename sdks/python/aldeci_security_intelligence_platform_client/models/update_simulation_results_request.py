from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="UpdateSimulationResultsRequest")


@_attrs_define
class UpdateSimulationResultsRequest:
    """
    Attributes:
        opened (int):
        clicked (int):
        reported (int):
    """

    opened: int
    clicked: int
    reported: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        opened = self.opened

        clicked = self.clicked

        reported = self.reported

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "opened": opened,
                "clicked": clicked,
                "reported": reported,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        opened = d.pop("opened")

        clicked = d.pop("clicked")

        reported = d.pop("reported")

        update_simulation_results_request = cls(
            opened=opened,
            clicked=clicked,
            reported=reported,
        )

        update_simulation_results_request.additional_properties = d
        return update_simulation_results_request

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
