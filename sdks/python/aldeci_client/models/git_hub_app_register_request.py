from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GitHubAppRegisterRequest")


@_attrs_define
class GitHubAppRegisterRequest:
    """
    Attributes:
        org_id (str):
        app_id (str):
        installation_id (str):
        webhook_secret (str): Raw webhook secret. Stored hashed (SHA-256). GitHub's X-Hub-Signature-256 must be computed
            using this secret as the HMAC key.
        app_slug (None | str | Unset):  Default: ''.
    """

    org_id: str
    app_id: str
    installation_id: str
    webhook_secret: str
    app_slug: None | str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        app_id = self.app_id

        installation_id = self.installation_id

        webhook_secret = self.webhook_secret

        app_slug: None | str | Unset
        if isinstance(self.app_slug, Unset):
            app_slug = UNSET
        else:
            app_slug = self.app_slug

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "app_id": app_id,
                "installation_id": installation_id,
                "webhook_secret": webhook_secret,
            }
        )
        if app_slug is not UNSET:
            field_dict["app_slug"] = app_slug

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        app_id = d.pop("app_id")

        installation_id = d.pop("installation_id")

        webhook_secret = d.pop("webhook_secret")

        def _parse_app_slug(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        app_slug = _parse_app_slug(d.pop("app_slug", UNSET))

        git_hub_app_register_request = cls(
            org_id=org_id,
            app_id=app_id,
            installation_id=installation_id,
            webhook_secret=webhook_secret,
            app_slug=app_slug,
        )

        git_hub_app_register_request.additional_properties = d
        return git_hub_app_register_request

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
