from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.onboarding_progress_response_steps import OnboardingProgressResponseSteps


T = TypeVar("T", bound="OnboardingProgressResponse")


@_attrs_define
class OnboardingProgressResponse:
    """
    Attributes:
        org_id (str):
        current_step (str):
        steps (OnboardingProgressResponseSteps):
        started_at (str):
        completion_percentage (float):
        completed_at (None | str | Unset):
    """

    org_id: str
    current_step: str
    steps: OnboardingProgressResponseSteps
    started_at: str
    completion_percentage: float
    completed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        current_step = self.current_step

        steps = self.steps.to_dict()

        started_at = self.started_at

        completion_percentage = self.completion_percentage

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "current_step": current_step,
                "steps": steps,
                "started_at": started_at,
                "completion_percentage": completion_percentage,
            }
        )
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.onboarding_progress_response_steps import OnboardingProgressResponseSteps

        d = dict(src_dict)
        org_id = d.pop("org_id")

        current_step = d.pop("current_step")

        steps = OnboardingProgressResponseSteps.from_dict(d.pop("steps"))

        started_at = d.pop("started_at")

        completion_percentage = d.pop("completion_percentage")

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        onboarding_progress_response = cls(
            org_id=org_id,
            current_step=current_step,
            steps=steps,
            started_at=started_at,
            completion_percentage=completion_percentage,
            completed_at=completed_at,
        )

        onboarding_progress_response.additional_properties = d
        return onboarding_progress_response

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
