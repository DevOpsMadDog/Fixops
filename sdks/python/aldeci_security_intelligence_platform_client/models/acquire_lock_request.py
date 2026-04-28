from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AcquireLockRequest")


@_attrs_define
class AcquireLockRequest:
    """
    Attributes:
        repo_path (str): Absolute path to repo root
        timeout (float | Unset):  Default: 30.0.
    """

    repo_path: str
    timeout: float | Unset = 30.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_path = self.repo_path

        timeout = self.timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_path": repo_path,
            }
        )
        if timeout is not UNSET:
            field_dict["timeout"] = timeout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        repo_path = d.pop("repo_path")

        timeout = d.pop("timeout", UNSET)

        acquire_lock_request = cls(
            repo_path=repo_path,
            timeout=timeout,
        )

        acquire_lock_request.additional_properties = d
        return acquire_lock_request

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
