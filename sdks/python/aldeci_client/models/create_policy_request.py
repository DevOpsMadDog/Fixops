from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_policy_request_settings import CreatePolicyRequestSettings


T = TypeVar("T", bound="CreatePolicyRequest")


@_attrs_define
class CreatePolicyRequest:
    """
    Attributes:
        policy_name (str):
        browser_type (str | Unset):  Default: 'all'.
        enforcement_level (str | Unset):  Default: 'recommended'.
        settings (CreatePolicyRequestSettings | Unset):
        status (str | Unset):  Default: 'active'.
    """

    policy_name: str
    browser_type: str | Unset = "all"
    enforcement_level: str | Unset = "recommended"
    settings: CreatePolicyRequestSettings | Unset = UNSET
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_name = self.policy_name

        browser_type = self.browser_type

        enforcement_level = self.enforcement_level

        settings: dict[str, Any] | Unset = UNSET
        if not isinstance(self.settings, Unset):
            settings = self.settings.to_dict()

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_name": policy_name,
            }
        )
        if browser_type is not UNSET:
            field_dict["browser_type"] = browser_type
        if enforcement_level is not UNSET:
            field_dict["enforcement_level"] = enforcement_level
        if settings is not UNSET:
            field_dict["settings"] = settings
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_policy_request_settings import CreatePolicyRequestSettings

        d = dict(src_dict)
        policy_name = d.pop("policy_name")

        browser_type = d.pop("browser_type", UNSET)

        enforcement_level = d.pop("enforcement_level", UNSET)

        _settings = d.pop("settings", UNSET)
        settings: CreatePolicyRequestSettings | Unset
        if isinstance(_settings, Unset):
            settings = UNSET
        else:
            settings = CreatePolicyRequestSettings.from_dict(_settings)

        status = d.pop("status", UNSET)

        create_policy_request = cls(
            policy_name=policy_name,
            browser_type=browser_type,
            enforcement_level=enforcement_level,
            settings=settings,
            status=status,
        )

        create_policy_request.additional_properties = d
        return create_policy_request

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
