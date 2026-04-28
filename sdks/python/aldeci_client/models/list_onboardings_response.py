from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.onboarding_progress_response import OnboardingProgressResponse


T = TypeVar("T", bound="ListOnboardingsResponse")


@_attrs_define
class ListOnboardingsResponse:
    """
    Attributes:
        onboardings (list[OnboardingProgressResponse]):
        total (int):
    """

    onboardings: list[OnboardingProgressResponse]
    total: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        onboardings = []
        for onboardings_item_data in self.onboardings:
            onboardings_item = onboardings_item_data.to_dict()
            onboardings.append(onboardings_item)

        total = self.total

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "onboardings": onboardings,
                "total": total,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.onboarding_progress_response import OnboardingProgressResponse

        d = dict(src_dict)
        onboardings = []
        _onboardings = d.pop("onboardings")
        for onboardings_item_data in _onboardings:
            onboardings_item = OnboardingProgressResponse.from_dict(onboardings_item_data)

            onboardings.append(onboardings_item)

        total = d.pop("total")

        list_onboardings_response = cls(
            onboardings=onboardings,
            total=total,
        )

        list_onboardings_response.additional_properties = d
        return list_onboardings_response

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
