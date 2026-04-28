from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="LaunchPhishingRequest")


@_attrs_define
class LaunchPhishingRequest:
    """
    Attributes:
        user_ids (list[str]): User IDs to target
        template (str): Phishing template ID (e.g. 'tpl_cred_001')
    """

    user_ids: list[str]
    template: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_ids = self.user_ids

        template = self.template

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_ids": user_ids,
                "template": template,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_ids = cast(list[str], d.pop("user_ids"))

        template = d.pop("template")

        launch_phishing_request = cls(
            user_ids=user_ids,
            template=template,
        )

        launch_phishing_request.additional_properties = d
        return launch_phishing_request

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
