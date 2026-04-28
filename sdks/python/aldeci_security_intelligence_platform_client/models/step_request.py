from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="StepRequest")


@_attrs_define
class StepRequest:
    """
    Attributes:
        step_order (int): Ordinal of this step in the run
        step_name (str): Human-readable step name
        step_type (str): build|test|lint|scan|sign|publish|deploy
        image (str | Unset): Container image used to run the step Default: ''.
        command (str | Unset): Command executed by the step Default: ''.
        config_hash (str | Unset): Hash of step config (YAML/JSON) Default: ''.
        duration_ms (int | Unset):  Default: 0.
        outcome (str | Unset): success|failed|skipped|cancelled|neutral Default: 'neutral'.
    """

    step_order: int
    step_name: str
    step_type: str
    image: str | Unset = ""
    command: str | Unset = ""
    config_hash: str | Unset = ""
    duration_ms: int | Unset = 0
    outcome: str | Unset = "neutral"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        step_order = self.step_order

        step_name = self.step_name

        step_type = self.step_type

        image = self.image

        command = self.command

        config_hash = self.config_hash

        duration_ms = self.duration_ms

        outcome = self.outcome

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "step_order": step_order,
                "step_name": step_name,
                "step_type": step_type,
            }
        )
        if image is not UNSET:
            field_dict["image"] = image
        if command is not UNSET:
            field_dict["command"] = command
        if config_hash is not UNSET:
            field_dict["config_hash"] = config_hash
        if duration_ms is not UNSET:
            field_dict["duration_ms"] = duration_ms
        if outcome is not UNSET:
            field_dict["outcome"] = outcome

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        step_order = d.pop("step_order")

        step_name = d.pop("step_name")

        step_type = d.pop("step_type")

        image = d.pop("image", UNSET)

        command = d.pop("command", UNSET)

        config_hash = d.pop("config_hash", UNSET)

        duration_ms = d.pop("duration_ms", UNSET)

        outcome = d.pop("outcome", UNSET)

        step_request = cls(
            step_order=step_order,
            step_name=step_name,
            step_type=step_type,
            image=image,
            command=command,
            config_hash=config_hash,
            duration_ms=duration_ms,
            outcome=outcome,
        )

        step_request.additional_properties = d
        return step_request

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
