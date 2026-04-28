from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.playbook_step_response_config import PlaybookStepResponseConfig


T = TypeVar("T", bound="PlaybookStepResponse")


@_attrs_define
class PlaybookStepResponse:
    """Response model for a playbook step.

    Attributes:
        step_id (str):
        step_type (str):
        name (str):
        config (PlaybookStepResponseConfig):
        timeout_seconds (int):
        next_on_success (None | str | Unset):
        next_on_failure (None | str | Unset):
    """

    step_id: str
    step_type: str
    name: str
    config: PlaybookStepResponseConfig
    timeout_seconds: int
    next_on_success: None | str | Unset = UNSET
    next_on_failure: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        step_id = self.step_id

        step_type = self.step_type

        name = self.name

        config = self.config.to_dict()

        timeout_seconds = self.timeout_seconds

        next_on_success: None | str | Unset
        if isinstance(self.next_on_success, Unset):
            next_on_success = UNSET
        else:
            next_on_success = self.next_on_success

        next_on_failure: None | str | Unset
        if isinstance(self.next_on_failure, Unset):
            next_on_failure = UNSET
        else:
            next_on_failure = self.next_on_failure

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "step_id": step_id,
                "step_type": step_type,
                "name": name,
                "config": config,
                "timeout_seconds": timeout_seconds,
            }
        )
        if next_on_success is not UNSET:
            field_dict["next_on_success"] = next_on_success
        if next_on_failure is not UNSET:
            field_dict["next_on_failure"] = next_on_failure

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.playbook_step_response_config import PlaybookStepResponseConfig

        d = dict(src_dict)
        step_id = d.pop("step_id")

        step_type = d.pop("step_type")

        name = d.pop("name")

        config = PlaybookStepResponseConfig.from_dict(d.pop("config"))

        timeout_seconds = d.pop("timeout_seconds")

        def _parse_next_on_success(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_on_success = _parse_next_on_success(d.pop("next_on_success", UNSET))

        def _parse_next_on_failure(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        next_on_failure = _parse_next_on_failure(d.pop("next_on_failure", UNSET))

        playbook_step_response = cls(
            step_id=step_id,
            step_type=step_type,
            name=name,
            config=config,
            timeout_seconds=timeout_seconds,
            next_on_success=next_on_success,
            next_on_failure=next_on_failure,
        )

        playbook_step_response.additional_properties = d
        return playbook_step_response

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
