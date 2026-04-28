from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.baseline_create_expected_config import BaselineCreateExpectedConfig


T = TypeVar("T", bound="BaselineCreate")


@_attrs_define
class BaselineCreate:
    """
    Attributes:
        resource_id (str): Cloud resource identifier
        resource_type (str | Unset): ec2 / s3 / rds / lambda / sg / vpc Default: 'ec2'.
        resource_name (str | Unset): Human-readable resource name Default: ''.
        expected_config (BaselineCreateExpectedConfig | Unset): Expected configuration from IaC
        source (str | Unset): terraform / cloudformation / manual Default: 'terraform'.
        environment (str | Unset): prod / staging / dev Default: 'prod'.
    """

    resource_id: str
    resource_type: str | Unset = "ec2"
    resource_name: str | Unset = ""
    expected_config: BaselineCreateExpectedConfig | Unset = UNSET
    source: str | Unset = "terraform"
    environment: str | Unset = "prod"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        resource_id = self.resource_id

        resource_type = self.resource_type

        resource_name = self.resource_name

        expected_config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.expected_config, Unset):
            expected_config = self.expected_config.to_dict()

        source = self.source

        environment = self.environment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "resource_id": resource_id,
            }
        )
        if resource_type is not UNSET:
            field_dict["resource_type"] = resource_type
        if resource_name is not UNSET:
            field_dict["resource_name"] = resource_name
        if expected_config is not UNSET:
            field_dict["expected_config"] = expected_config
        if source is not UNSET:
            field_dict["source"] = source
        if environment is not UNSET:
            field_dict["environment"] = environment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.baseline_create_expected_config import BaselineCreateExpectedConfig

        d = dict(src_dict)
        resource_id = d.pop("resource_id")

        resource_type = d.pop("resource_type", UNSET)

        resource_name = d.pop("resource_name", UNSET)

        _expected_config = d.pop("expected_config", UNSET)
        expected_config: BaselineCreateExpectedConfig | Unset
        if isinstance(_expected_config, Unset):
            expected_config = UNSET
        else:
            expected_config = BaselineCreateExpectedConfig.from_dict(_expected_config)

        source = d.pop("source", UNSET)

        environment = d.pop("environment", UNSET)

        baseline_create = cls(
            resource_id=resource_id,
            resource_type=resource_type,
            resource_name=resource_name,
            expected_config=expected_config,
            source=source,
            environment=environment,
        )

        baseline_create.additional_properties = d
        return baseline_create

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
