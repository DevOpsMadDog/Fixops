from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.severity import Severity
from ..types import UNSET, Unset

T = TypeVar("T", bound="GatingPolicy")


@_attrs_define
class GatingPolicy:
    """Policy that determines pass/fail for PR and CI/CD gates.

    Attributes:
        fail_on (Severity | Unset):
        warn_on (Severity | Unset):
        max_critical (int | Unset): Maximum allowed critical findings Default: 0.
        max_high (int | Unset): Maximum allowed high findings Default: 0.
        max_medium (int | None | Unset): Maximum allowed medium findings (None = unlimited)
        block_secrets (bool | Unset): Always block if secrets detected Default: True.
        block_unreachable (bool | Unset): Block on unreachable findings too (default: skip them) Default: False.
        require_sbom (bool | Unset): Require SBOM in gate evaluation Default: False.
        categories (list[str] | Unset): Finding categories to evaluate
    """

    fail_on: Severity | Unset = UNSET
    warn_on: Severity | Unset = UNSET
    max_critical: int | Unset = 0
    max_high: int | Unset = 0
    max_medium: int | None | Unset = UNSET
    block_secrets: bool | Unset = True
    block_unreachable: bool | Unset = False
    require_sbom: bool | Unset = False
    categories: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fail_on: str | Unset = UNSET
        if not isinstance(self.fail_on, Unset):
            fail_on = self.fail_on.value

        warn_on: str | Unset = UNSET
        if not isinstance(self.warn_on, Unset):
            warn_on = self.warn_on.value

        max_critical = self.max_critical

        max_high = self.max_high

        max_medium: int | None | Unset
        if isinstance(self.max_medium, Unset):
            max_medium = UNSET
        else:
            max_medium = self.max_medium

        block_secrets = self.block_secrets

        block_unreachable = self.block_unreachable

        require_sbom = self.require_sbom

        categories: list[str] | Unset = UNSET
        if not isinstance(self.categories, Unset):
            categories = self.categories

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
        if block_secrets is not UNSET:
            field_dict["block_secrets"] = block_secrets
        if block_unreachable is not UNSET:
            field_dict["block_unreachable"] = block_unreachable
        if require_sbom is not UNSET:
            field_dict["require_sbom"] = require_sbom
        if categories is not UNSET:
            field_dict["categories"] = categories

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        _fail_on = d.pop("fail_on", UNSET)
        fail_on: Severity | Unset
        if isinstance(_fail_on, Unset):
            fail_on = UNSET
        else:
            fail_on = Severity(_fail_on)

        _warn_on = d.pop("warn_on", UNSET)
        warn_on: Severity | Unset
        if isinstance(_warn_on, Unset):
            warn_on = UNSET
        else:
            warn_on = Severity(_warn_on)

        max_critical = d.pop("max_critical", UNSET)

        max_high = d.pop("max_high", UNSET)

        def _parse_max_medium(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        max_medium = _parse_max_medium(d.pop("max_medium", UNSET))

        block_secrets = d.pop("block_secrets", UNSET)

        block_unreachable = d.pop("block_unreachable", UNSET)

        require_sbom = d.pop("require_sbom", UNSET)

        categories = cast(list[str], d.pop("categories", UNSET))

        gating_policy = cls(
            fail_on=fail_on,
            warn_on=warn_on,
            max_critical=max_critical,
            max_high=max_high,
            max_medium=max_medium,
            block_secrets=block_secrets,
            block_unreachable=block_unreachable,
            require_sbom=require_sbom,
            categories=categories,
        )

        gating_policy.additional_properties = d
        return gating_policy

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
