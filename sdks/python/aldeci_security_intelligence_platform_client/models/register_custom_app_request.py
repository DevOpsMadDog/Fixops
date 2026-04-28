from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.integration_category import IntegrationCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.register_custom_app_request_config_schema import RegisterCustomAppRequestConfigSchema


T = TypeVar("T", bound="RegisterCustomAppRequest")


@_attrs_define
class RegisterCustomAppRequest:
    """Request body for registering a custom/private integration.

    Attributes:
        id (str): Unique slug for this app
        name (str):
        description (str):
        category (IntegrationCategory): Category of a marketplace integration.
        author (str):
        version (str | Unset):  Default: '1.0'.
        icon_url (None | str | Unset):
        config_schema (RegisterCustomAppRequestConfigSchema | Unset):
        required_scopes (list[str] | Unset):
    """

    id: str
    name: str
    description: str
    category: IntegrationCategory
    author: str
    version: str | Unset = "1.0"
    icon_url: None | str | Unset = UNSET
    config_schema: RegisterCustomAppRequestConfigSchema | Unset = UNSET
    required_scopes: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        description = self.description

        category = self.category.value

        author = self.author

        version = self.version

        icon_url: None | str | Unset
        if isinstance(self.icon_url, Unset):
            icon_url = UNSET
        else:
            icon_url = self.icon_url

        config_schema: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config_schema, Unset):
            config_schema = self.config_schema.to_dict()

        required_scopes: list[str] | Unset = UNSET
        if not isinstance(self.required_scopes, Unset):
            required_scopes = self.required_scopes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "description": description,
                "category": category,
                "author": author,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if icon_url is not UNSET:
            field_dict["icon_url"] = icon_url
        if config_schema is not UNSET:
            field_dict["config_schema"] = config_schema
        if required_scopes is not UNSET:
            field_dict["required_scopes"] = required_scopes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.register_custom_app_request_config_schema import RegisterCustomAppRequestConfigSchema

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        description = d.pop("description")

        category = IntegrationCategory(d.pop("category"))

        author = d.pop("author")

        version = d.pop("version", UNSET)

        def _parse_icon_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        icon_url = _parse_icon_url(d.pop("icon_url", UNSET))

        _config_schema = d.pop("config_schema", UNSET)
        config_schema: RegisterCustomAppRequestConfigSchema | Unset
        if isinstance(_config_schema, Unset):
            config_schema = UNSET
        else:
            config_schema = RegisterCustomAppRequestConfigSchema.from_dict(_config_schema)

        required_scopes = cast(list[str], d.pop("required_scopes", UNSET))

        register_custom_app_request = cls(
            id=id,
            name=name,
            description=description,
            category=category,
            author=author,
            version=version,
            icon_url=icon_url,
            config_schema=config_schema,
            required_scopes=required_scopes,
        )

        register_custom_app_request.additional_properties = d
        return register_custom_app_request

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
