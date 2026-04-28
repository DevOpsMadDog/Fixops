from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.step_config_response_config import StepConfigResponseConfig


T = TypeVar("T", bound="StepConfigResponse")


@_attrs_define
class StepConfigResponse:
    """
    Attributes:
        org_id (str):
        step (str):
        config (StepConfigResponseConfig):
    """

    org_id: str
    step: str
    config: StepConfigResponseConfig
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        step = self.step

        config = self.config.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "step": step,
                "config": config,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.step_config_response_config import StepConfigResponseConfig

        d = dict(src_dict)
        org_id = d.pop("org_id")

        step = d.pop("step")

        config = StepConfigResponseConfig.from_dict(d.pop("config"))

        step_config_response = cls(
            org_id=org_id,
            step=step,
            config=config,
        )

        step_config_response.additional_properties = d
        return step_config_response

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
