from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.integration_status import IntegrationStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.integration_update_config_type_0 import IntegrationUpdateConfigType0


T = TypeVar("T", bound="IntegrationUpdate")


@_attrs_define
class IntegrationUpdate:
    """Request model for updating an integration.

    Attributes:
        name (None | str | Unset):
        status (IntegrationStatus | None | Unset):
        config (IntegrationUpdateConfigType0 | None | Unset):
    """

    name: None | str | Unset = UNSET
    status: IntegrationStatus | None | Unset = UNSET
    config: IntegrationUpdateConfigType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.integration_update_config_type_0 import IntegrationUpdateConfigType0

        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, IntegrationStatus):
            status = self.status.value
        else:
            status = self.status

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, IntegrationUpdateConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if status is not UNSET:
            field_dict["status"] = status
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.integration_update_config_type_0 import IntegrationUpdateConfigType0

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_status(data: object) -> IntegrationStatus | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = IntegrationStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(IntegrationStatus | None | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_config(data: object) -> IntegrationUpdateConfigType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = IntegrationUpdateConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(IntegrationUpdateConfigType0 | None | Unset, data)

        config = _parse_config(d.pop("config", UNSET))

        integration_update = cls(
            name=name,
            status=status,
            config=config,
        )

        integration_update.additional_properties = d
        return integration_update

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
