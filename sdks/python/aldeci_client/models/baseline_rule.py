from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.cloud_provider import CloudProvider
from ..models.drift_severity import DriftSeverity
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.baseline_rule_expected_config import BaselineRuleExpectedConfig


T = TypeVar("T", bound="BaselineRule")


@_attrs_define
class BaselineRule:
    """A security baseline rule to compare resources against.

    Attributes:
        name (str):
        description (str):
        provider (CloudProvider):
        resource_type (str):
        expected_config (BaselineRuleExpectedConfig):
        severity (DriftSeverity):
        remediation (str):
        id (str | Unset):
        cis_benchmark (None | str | Unset):
    """

    name: str
    description: str
    provider: CloudProvider
    resource_type: str
    expected_config: BaselineRuleExpectedConfig
    severity: DriftSeverity
    remediation: str
    id: str | Unset = UNSET
    cis_benchmark: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        provider = self.provider.value

        resource_type = self.resource_type

        expected_config = self.expected_config.to_dict()

        severity = self.severity.value

        remediation = self.remediation

        id = self.id

        cis_benchmark: None | str | Unset
        if isinstance(self.cis_benchmark, Unset):
            cis_benchmark = UNSET
        else:
            cis_benchmark = self.cis_benchmark

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "description": description,
                "provider": provider,
                "resource_type": resource_type,
                "expected_config": expected_config,
                "severity": severity,
                "remediation": remediation,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if cis_benchmark is not UNSET:
            field_dict["cis_benchmark"] = cis_benchmark

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.baseline_rule_expected_config import BaselineRuleExpectedConfig

        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description")

        provider = CloudProvider(d.pop("provider"))

        resource_type = d.pop("resource_type")

        expected_config = BaselineRuleExpectedConfig.from_dict(d.pop("expected_config"))

        severity = DriftSeverity(d.pop("severity"))

        remediation = d.pop("remediation")

        id = d.pop("id", UNSET)

        def _parse_cis_benchmark(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cis_benchmark = _parse_cis_benchmark(d.pop("cis_benchmark", UNSET))

        baseline_rule = cls(
            name=name,
            description=description,
            provider=provider,
            resource_type=resource_type,
            expected_config=expected_config,
            severity=severity,
            remediation=remediation,
            id=id,
            cis_benchmark=cis_benchmark,
        )

        baseline_rule.additional_properties = d
        return baseline_rule

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
