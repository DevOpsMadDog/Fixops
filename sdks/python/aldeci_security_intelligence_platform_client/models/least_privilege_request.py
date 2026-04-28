from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.least_privilege_request_usage_log_type_0_item import LeastPrivilegeRequestUsageLogType0Item


T = TypeVar("T", bound="LeastPrivilegeRequest")


@_attrs_define
class LeastPrivilegeRequest:
    """
    Attributes:
        org_id (str | Unset): Organization identifier Default: 'default'.
        current_permissions (list[str] | None | Unset): Permissions currently granted to the identity
        used_permissions (list[str] | None | Unset): Permissions actually used (explicit)
        usage_log (list[LeastPrivilegeRequestUsageLogType0Item] | None | Unset): Usage log rows [{action, timestamp}] —
            actions in the last window_days are used
        window_days (int | Unset): Look-back window in days Default: 90.
    """

    org_id: str | Unset = "default"
    current_permissions: list[str] | None | Unset = UNSET
    used_permissions: list[str] | None | Unset = UNSET
    usage_log: list[LeastPrivilegeRequestUsageLogType0Item] | None | Unset = UNSET
    window_days: int | Unset = 90
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        current_permissions: list[str] | None | Unset
        if isinstance(self.current_permissions, Unset):
            current_permissions = UNSET
        elif isinstance(self.current_permissions, list):
            current_permissions = self.current_permissions

        else:
            current_permissions = self.current_permissions

        used_permissions: list[str] | None | Unset
        if isinstance(self.used_permissions, Unset):
            used_permissions = UNSET
        elif isinstance(self.used_permissions, list):
            used_permissions = self.used_permissions

        else:
            used_permissions = self.used_permissions

        usage_log: list[dict[str, Any]] | None | Unset
        if isinstance(self.usage_log, Unset):
            usage_log = UNSET
        elif isinstance(self.usage_log, list):
            usage_log = []
            for usage_log_type_0_item_data in self.usage_log:
                usage_log_type_0_item = usage_log_type_0_item_data.to_dict()
                usage_log.append(usage_log_type_0_item)

        else:
            usage_log = self.usage_log

        window_days = self.window_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if current_permissions is not UNSET:
            field_dict["current_permissions"] = current_permissions
        if used_permissions is not UNSET:
            field_dict["used_permissions"] = used_permissions
        if usage_log is not UNSET:
            field_dict["usage_log"] = usage_log
        if window_days is not UNSET:
            field_dict["window_days"] = window_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.least_privilege_request_usage_log_type_0_item import LeastPrivilegeRequestUsageLogType0Item

        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        def _parse_current_permissions(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                current_permissions_type_0 = cast(list[str], data)

                return current_permissions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        current_permissions = _parse_current_permissions(d.pop("current_permissions", UNSET))

        def _parse_used_permissions(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                used_permissions_type_0 = cast(list[str], data)

                return used_permissions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        used_permissions = _parse_used_permissions(d.pop("used_permissions", UNSET))

        def _parse_usage_log(data: object) -> list[LeastPrivilegeRequestUsageLogType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                usage_log_type_0 = []
                _usage_log_type_0 = data
                for usage_log_type_0_item_data in _usage_log_type_0:
                    usage_log_type_0_item = LeastPrivilegeRequestUsageLogType0Item.from_dict(usage_log_type_0_item_data)

                    usage_log_type_0.append(usage_log_type_0_item)

                return usage_log_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[LeastPrivilegeRequestUsageLogType0Item] | None | Unset, data)

        usage_log = _parse_usage_log(d.pop("usage_log", UNSET))

        window_days = d.pop("window_days", UNSET)

        least_privilege_request = cls(
            org_id=org_id,
            current_permissions=current_permissions,
            used_permissions=used_permissions,
            usage_log=usage_log,
            window_days=window_days,
        )

        least_privilege_request.additional_properties = d
        return least_privilege_request

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
