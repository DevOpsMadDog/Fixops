from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DiscoverAppRequest")


@_attrs_define
class DiscoverAppRequest:
    """
    Attributes:
        app_name (str): Cloud application name (e.g. 'Dropbox')
        org_id (str | Unset): Organisation ID Default: 'default'.
        app_category (str | Unset): Category: productivity/collaboration/storage/crm/devtools/social/other Default:
            'other'.
        risk_level (str | Unset): Risk level: critical/high/medium/low Default: 'medium'.
        users_count (int | Unset): Number of users using the app Default: 0.
        data_uploaded_gb (float | Unset): Data uploaded in GB Default: 0.0.
        is_sanctioned (bool | Unset): Whether the app is sanctioned Default: False.
        oauth_scopes (list[str] | Unset): OAuth permission scopes granted
    """

    app_name: str
    org_id: str | Unset = "default"
    app_category: str | Unset = "other"
    risk_level: str | Unset = "medium"
    users_count: int | Unset = 0
    data_uploaded_gb: float | Unset = 0.0
    is_sanctioned: bool | Unset = False
    oauth_scopes: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_name = self.app_name

        org_id = self.org_id

        app_category = self.app_category

        risk_level = self.risk_level

        users_count = self.users_count

        data_uploaded_gb = self.data_uploaded_gb

        is_sanctioned = self.is_sanctioned

        oauth_scopes: list[str] | Unset = UNSET
        if not isinstance(self.oauth_scopes, Unset):
            oauth_scopes = self.oauth_scopes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_name": app_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if app_category is not UNSET:
            field_dict["app_category"] = app_category
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if users_count is not UNSET:
            field_dict["users_count"] = users_count
        if data_uploaded_gb is not UNSET:
            field_dict["data_uploaded_gb"] = data_uploaded_gb
        if is_sanctioned is not UNSET:
            field_dict["is_sanctioned"] = is_sanctioned
        if oauth_scopes is not UNSET:
            field_dict["oauth_scopes"] = oauth_scopes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_name = d.pop("app_name")

        org_id = d.pop("org_id", UNSET)

        app_category = d.pop("app_category", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        users_count = d.pop("users_count", UNSET)

        data_uploaded_gb = d.pop("data_uploaded_gb", UNSET)

        is_sanctioned = d.pop("is_sanctioned", UNSET)

        oauth_scopes = cast(list[str], d.pop("oauth_scopes", UNSET))

        discover_app_request = cls(
            app_name=app_name,
            org_id=org_id,
            app_category=app_category,
            risk_level=risk_level,
            users_count=users_count,
            data_uploaded_gb=data_uploaded_gb,
            is_sanctioned=is_sanctioned,
            oauth_scopes=oauth_scopes,
        )

        discover_app_request.additional_properties = d
        return discover_app_request

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
