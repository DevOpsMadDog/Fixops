from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.gate_severity import GateSeverity
from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyThresholds")


@_attrs_define
class PolicyThresholds:
    """Configurable severity thresholds for gate decisions.

    Attributes:
        fail_on (list[GateSeverity] | Unset): Severities that cause a gate FAIL
        warn_on (list[GateSeverity] | Unset): Severities that produce warnings but don't block
        max_critical (int | Unset): Max critical findings before FAIL Default: 0.
        max_high (int | Unset): Max high findings before FAIL Default: 0.
        max_medium (int | None | Unset): Max medium findings (None = unlimited)
        max_total (int | None | Unset): Max total findings (None = unlimited)
        require_sbom (bool | Unset): Require SBOM presence to pass Default: False.
        block_on_license_violation (bool | Unset): Block if license violations found Default: False.
    """

    fail_on: list[GateSeverity] | Unset = UNSET
    warn_on: list[GateSeverity] | Unset = UNSET
    max_critical: int | Unset = 0
    max_high: int | Unset = 0
    max_medium: int | None | Unset = UNSET
    max_total: int | None | Unset = UNSET
    require_sbom: bool | Unset = False
    block_on_license_violation: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fail_on: list[str] | Unset = UNSET
        if not isinstance(self.fail_on, Unset):
            fail_on = []
            for fail_on_item_data in self.fail_on:
                fail_on_item = fail_on_item_data.value
                fail_on.append(fail_on_item)

        warn_on: list[str] | Unset = UNSET
        if not isinstance(self.warn_on, Unset):
            warn_on = []
            for warn_on_item_data in self.warn_on:
                warn_on_item = warn_on_item_data.value
                warn_on.append(warn_on_item)

        max_critical = self.max_critical

        max_high = self.max_high

        max_medium: int | None | Unset
        if isinstance(self.max_medium, Unset):
            max_medium = UNSET
        else:
            max_medium = self.max_medium

        max_total: int | None | Unset
        if isinstance(self.max_total, Unset):
            max_total = UNSET
        else:
            max_total = self.max_total

        require_sbom = self.require_sbom

        block_on_license_violation = self.block_on_license_violation

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if fail_on is not UNSET:
            field_dict["fail_on"] = fail_on
        if warn_on is not UNSET:
            field_dict["warn_on"] = warn_on
        if max_critical is not UNSET:
            field_dict["max_critical"] = max_critical
        if max_high is not UNSET:
            field_dict["max_high"] = max_high
        if max_medium is not UNSET:
            field_dict["max_medium"] = max_medium
        if max_total is not UNSET:
            field_dict["max_total"] = max_total
        if require_sbom is not UNSET:
            field_dict["require_sbom"] = require_sbom
        if block_on_license_violation is not UNSET:
            field_dict["block_on_license_violation"] = block_on_license_violation

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _fail_on = d.pop("fail_on", UNSET)
        fail_on: list[GateSeverity] | Unset = UNSET
        if _fail_on is not UNSET:
            fail_on = []
            for fail_on_item_data in _fail_on:
                fail_on_item = GateSeverity(fail_on_item_data)

                fail_on.append(fail_on_item)

        _warn_on = d.pop("warn_on", UNSET)
        warn_on: list[GateSeverity] | Unset = UNSET
        if _warn_on is not UNSET:
            warn_on = []
            for warn_on_item_data in _warn_on:
                warn_on_item = GateSeverity(warn_on_item_data)

                warn_on.append(warn_on_item)

        max_critical = d.pop("max_critical", UNSET)

        max_high = d.pop("max_high", UNSET)

        def _parse_max_medium(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        max_medium = _parse_max_medium(d.pop("max_medium", UNSET))

        def _parse_max_total(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        max_total = _parse_max_total(d.pop("max_total", UNSET))

        require_sbom = d.pop("require_sbom", UNSET)

        block_on_license_violation = d.pop("block_on_license_violation", UNSET)

        policy_thresholds = cls(
            fail_on=fail_on,
            warn_on=warn_on,
            max_critical=max_critical,
            max_high=max_high,
            max_medium=max_medium,
            max_total=max_total,
            require_sbom=require_sbom,
            block_on_license_violation=block_on_license_violation,
        )

        policy_thresholds.additional_properties = d
        return policy_thresholds

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
