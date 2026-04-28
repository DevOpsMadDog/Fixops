from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.app_status import AppStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.installed_app_config import InstalledAppConfig


T = TypeVar("T", bound="InstalledApp")


@_attrs_define
class InstalledApp:
    """An integration installed by an organization.

    Attributes:
        app_id (str): References MarketplaceApp.id
        org_id (str): Organization that installed the app
        installed_by (str): User ID or service account that installed the app
        config (InstalledAppConfig | Unset): Runtime configuration (API keys, URLs, etc.)
        installed_at (datetime.datetime | Unset): When the app was installed
        status (AppStatus | Unset): Installation status of an app.
    """

    app_id: str
    org_id: str
    installed_by: str
    config: InstalledAppConfig | Unset = UNSET
    installed_at: datetime.datetime | Unset = UNSET
    status: AppStatus | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        org_id = self.org_id

        installed_by = self.installed_by

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        installed_at: str | Unset = UNSET
        if not isinstance(self.installed_at, Unset):
            installed_at = self.installed_at.isoformat()

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
                "org_id": org_id,
                "installed_by": installed_by,
            }
        )
        if config is not UNSET:
            field_dict["config"] = config
        if installed_at is not UNSET:
            field_dict["installed_at"] = installed_at
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.installed_app_config import InstalledAppConfig

        d = dict(src_dict)
        app_id = d.pop("app_id")

        org_id = d.pop("org_id")

        installed_by = d.pop("installed_by")

        _config = d.pop("config", UNSET)
        config: InstalledAppConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = InstalledAppConfig.from_dict(_config)

        _installed_at = d.pop("installed_at", UNSET)
        installed_at: datetime.datetime | Unset
        if isinstance(_installed_at, Unset):
            installed_at = UNSET
        else:
            installed_at = isoparse(_installed_at)

        _status = d.pop("status", UNSET)
        status: AppStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = AppStatus(_status)

        installed_app = cls(
            app_id=app_id,
            org_id=org_id,
            installed_by=installed_by,
            config=config,
            installed_at=installed_at,
            status=status,
        )

        installed_app.additional_properties = d
        return installed_app

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
