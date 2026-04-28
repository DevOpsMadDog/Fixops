from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_app_request_config_type_0 import RegisterAppRequestConfigType0


T = TypeVar("T", bound="RegisterAppRequest")


@_attrs_define
class RegisterAppRequest:
    """Payload for registering an app via raw aldeci.yaml text or a dict.

    Attributes:
        yaml_content (None | str | Unset): Raw aldeci.yaml content as a string
        config (None | RegisterAppRequestConfigType0 | Unset): Parsed config dict (alternative to yaml_content)
    """

    yaml_content: None | str | Unset = UNSET
    config: None | RegisterAppRequestConfigType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.register_app_request_config_type_0 import RegisterAppRequestConfigType0

        yaml_content: None | str | Unset
        if isinstance(self.yaml_content, Unset):
            yaml_content = UNSET
        else:
            yaml_content = self.yaml_content

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, RegisterAppRequestConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if yaml_content is not UNSET:
            field_dict["yaml_content"] = yaml_content
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_app_request_config_type_0 import RegisterAppRequestConfigType0

        d = dict(src_dict)

        def _parse_yaml_content(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        yaml_content = _parse_yaml_content(d.pop("yaml_content", UNSET))

        def _parse_config(data: object) -> None | RegisterAppRequestConfigType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = RegisterAppRequestConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | RegisterAppRequestConfigType0 | Unset, data)

        config = _parse_config(d.pop("config", UNSET))

        register_app_request = cls(
            yaml_content=yaml_content,
            config=config,
        )

        register_app_request.additional_properties = d
        return register_app_request

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
