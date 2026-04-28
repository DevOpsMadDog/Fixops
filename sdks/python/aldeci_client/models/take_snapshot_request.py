from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.take_snapshot_request_env_vars_type_0 import TakeSnapshotRequestEnvVarsType0


T = TypeVar("T", bound="TakeSnapshotRequest")


@_attrs_define
class TakeSnapshotRequest:
    """
    Attributes:
        target (str | Unset): Hostname or IP to snapshot Default: '127.0.0.1'.
        port_timeout (float | Unset): Per-port socket timeout in seconds Default: 0.1.
        endpoints (list[str] | None | Unset): Known endpoints to record
        deps (list[str] | None | Unset): Dependency list to record
        env_vars (None | TakeSnapshotRequestEnvVarsType0 | Unset): Environment variable key/value pairs to scan for
            secrets
    """

    target: str | Unset = "127.0.0.1"
    port_timeout: float | Unset = 0.1
    endpoints: list[str] | None | Unset = UNSET
    deps: list[str] | None | Unset = UNSET
    env_vars: None | TakeSnapshotRequestEnvVarsType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.take_snapshot_request_env_vars_type_0 import TakeSnapshotRequestEnvVarsType0

        target = self.target

        port_timeout = self.port_timeout

        endpoints: list[str] | None | Unset
        if isinstance(self.endpoints, Unset):
            endpoints = UNSET
        elif isinstance(self.endpoints, list):
            endpoints = self.endpoints

        else:
            endpoints = self.endpoints

        deps: list[str] | None | Unset
        if isinstance(self.deps, Unset):
            deps = UNSET
        elif isinstance(self.deps, list):
            deps = self.deps

        else:
            deps = self.deps

        env_vars: dict[str, Any] | None | Unset
        if isinstance(self.env_vars, Unset):
            env_vars = UNSET
        elif isinstance(self.env_vars, TakeSnapshotRequestEnvVarsType0):
            env_vars = self.env_vars.to_dict()
        else:
            env_vars = self.env_vars

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target is not UNSET:
            field_dict["target"] = target
        if port_timeout is not UNSET:
            field_dict["port_timeout"] = port_timeout
        if endpoints is not UNSET:
            field_dict["endpoints"] = endpoints
        if deps is not UNSET:
            field_dict["deps"] = deps
        if env_vars is not UNSET:
            field_dict["env_vars"] = env_vars

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.take_snapshot_request_env_vars_type_0 import TakeSnapshotRequestEnvVarsType0

        d = dict(src_dict)
        target = d.pop("target", UNSET)

        port_timeout = d.pop("port_timeout", UNSET)

        def _parse_endpoints(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                endpoints_type_0 = cast(list[str], data)

                return endpoints_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        endpoints = _parse_endpoints(d.pop("endpoints", UNSET))

        def _parse_deps(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                deps_type_0 = cast(list[str], data)

                return deps_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        deps = _parse_deps(d.pop("deps", UNSET))

        def _parse_env_vars(data: object) -> None | TakeSnapshotRequestEnvVarsType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                env_vars_type_0 = TakeSnapshotRequestEnvVarsType0.from_dict(data)

                return env_vars_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | TakeSnapshotRequestEnvVarsType0 | Unset, data)

        env_vars = _parse_env_vars(d.pop("env_vars", UNSET))

        take_snapshot_request = cls(
            target=target,
            port_timeout=port_timeout,
            endpoints=endpoints,
            deps=deps,
            env_vars=env_vars,
        )

        take_snapshot_request.additional_properties = d
        return take_snapshot_request

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
