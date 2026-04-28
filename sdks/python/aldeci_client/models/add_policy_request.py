from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_policy_request_config import AddPolicyRequestConfig


T = TypeVar("T", bound="AddPolicyRequest")


@_attrs_define
class AddPolicyRequest:
    """
    Attributes:
        policy_name (str):
        policy_type (str):
        config (AddPolicyRequestConfig | Unset):
    """

    policy_name: str
    policy_type: str
    config: AddPolicyRequestConfig | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_name = self.policy_name

        policy_type = self.policy_type

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_name": policy_name,
                "policy_type": policy_type,
            }
        )
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_policy_request_config import AddPolicyRequestConfig

        d = dict(src_dict)
        policy_name = d.pop("policy_name")

        policy_type = d.pop("policy_type")

        _config = d.pop("config", UNSET)
        config: AddPolicyRequestConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = AddPolicyRequestConfig.from_dict(_config)

        add_policy_request = cls(
            policy_name=policy_name,
            policy_type=policy_type,
            config=config,
        )

        add_policy_request.additional_properties = d
        return add_policy_request

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
