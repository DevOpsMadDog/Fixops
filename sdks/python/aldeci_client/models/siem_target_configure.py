from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.siem_target_configure_config import SIEMTargetConfigureConfig


T = TypeVar("T", bound="SIEMTargetConfigure")


@_attrs_define
class SIEMTargetConfigure:
    """
    Attributes:
        name (str):
        siem_type (str): splunk_hec | sentinel | generic
        org_id (str | Unset):  Default: 'default'.
        config (SIEMTargetConfigureConfig | Unset): Connector-specific config (url, token, tenant_id, etc.)
    """

    name: str
    siem_type: str
    org_id: str | Unset = "default"
    config: SIEMTargetConfigureConfig | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        siem_type = self.siem_type

        org_id = self.org_id

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "siem_type": siem_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.siem_target_configure_config import SIEMTargetConfigureConfig

        d = dict(src_dict)
        name = d.pop("name")

        siem_type = d.pop("siem_type")

        org_id = d.pop("org_id", UNSET)

        _config = d.pop("config", UNSET)
        config: SIEMTargetConfigureConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = SIEMTargetConfigureConfig.from_dict(_config)

        siem_target_configure = cls(
            name=name,
            siem_type=siem_type,
            org_id=org_id,
            config=config,
        )

        siem_target_configure.additional_properties = d
        return siem_target_configure

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
