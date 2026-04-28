from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="HookUninstallRequest")


@_attrs_define
class HookUninstallRequest:
    """Body for POST /api/v1/hooks/uninstall.

    At least one of ``hook_id``, ``policy_hash``, or ``org_id`` must be
    supplied. ``org_id`` may also be supplied via the ``X-Org-ID`` header.

        Attributes:
            hook_id (None | str | Unset): Specific hook policy record id (returned by /hooks-yaml/apply).
            policy_hash (None | str | Unset): SHA-256 (or other content) hash of the policy to remove.
            org_id (None | str | Unset): Org/tenant id. Required if not supplied via X-Org-ID header.
            reason (None | str | Unset): Audit reason recorded with the tombstone.
    """

    hook_id: None | str | Unset = UNSET
    policy_hash: None | str | Unset = UNSET
    org_id: None | str | Unset = UNSET
    reason: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hook_id: None | str | Unset
        if isinstance(self.hook_id, Unset):
            hook_id = UNSET
        else:
            hook_id = self.hook_id

        policy_hash: None | str | Unset
        if isinstance(self.policy_hash, Unset):
            policy_hash = UNSET
        else:
            policy_hash = self.policy_hash

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if hook_id is not UNSET:
            field_dict["hook_id"] = hook_id
        if policy_hash is not UNSET:
            field_dict["policy_hash"] = policy_hash
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_hook_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        hook_id = _parse_hook_id(d.pop("hook_id", UNSET))

        def _parse_policy_hash(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_hash = _parse_policy_hash(d.pop("policy_hash", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        hook_uninstall_request = cls(
            hook_id=hook_id,
            policy_hash=policy_hash,
            org_id=org_id,
            reason=reason,
        )

        hook_uninstall_request.additional_properties = d
        return hook_uninstall_request

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
