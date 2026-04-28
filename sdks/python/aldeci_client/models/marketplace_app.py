from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.integration_category import IntegrationCategory
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.marketplace_app_config_schema import MarketplaceAppConfigSchema


T = TypeVar("T", bound="MarketplaceApp")


@_attrs_define
class MarketplaceApp:
    """Available integration in the marketplace catalog.

    Attributes:
        id (str): Unique app identifier (slug)
        name (str): Human-readable name
        description (str): Brief description of what the integration does
        category (IntegrationCategory): Category of a marketplace integration.
        version (str): Latest available version
        author (str): Publisher / maintainer name
        icon_url (None | str | Unset): URL to the app's logo or icon
        config_schema (MarketplaceAppConfigSchema | Unset): JSON Schema describing required configuration fields
        required_scopes (list[str] | Unset): OAuth / permission scopes needed by this integration
        install_count (int | Unset): Total install count across all orgs Default: 0.
        rating (float | Unset): Average user rating (0-5) Default: 0.0.
        org_id (None | str | Unset): If set, this is a private/custom app visible only to this org
    """

    id: str
    name: str
    description: str
    category: IntegrationCategory
    version: str
    author: str
    icon_url: None | str | Unset = UNSET
    config_schema: MarketplaceAppConfigSchema | Unset = UNSET
    required_scopes: list[str] | Unset = UNSET
    install_count: int | Unset = 0
    rating: float | Unset = 0.0
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id = self.id

        name = self.name

        description = self.description

        category = self.category.value

        version = self.version

        author = self.author

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

        install_count = self.install_count

        rating = self.rating

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "name": name,
                "description": description,
                "category": category,
                "version": version,
                "author": author,
            }
        )
        if icon_url is not UNSET:
            field_dict["icon_url"] = icon_url
        if config_schema is not UNSET:
            field_dict["config_schema"] = config_schema
        if required_scopes is not UNSET:
            field_dict["required_scopes"] = required_scopes
        if install_count is not UNSET:
            field_dict["install_count"] = install_count
        if rating is not UNSET:
            field_dict["rating"] = rating
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.marketplace_app_config_schema import MarketplaceAppConfigSchema

        d = dict(src_dict)
        id = d.pop("id")

        name = d.pop("name")

        description = d.pop("description")

        category = IntegrationCategory(d.pop("category"))

        version = d.pop("version")

        author = d.pop("author")

        def _parse_icon_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        icon_url = _parse_icon_url(d.pop("icon_url", UNSET))

        _config_schema = d.pop("config_schema", UNSET)
        config_schema: MarketplaceAppConfigSchema | Unset
        if isinstance(_config_schema, Unset):
            config_schema = UNSET
        else:
            config_schema = MarketplaceAppConfigSchema.from_dict(_config_schema)

        required_scopes = cast(list[str], d.pop("required_scopes", UNSET))

        install_count = d.pop("install_count", UNSET)

        rating = d.pop("rating", UNSET)

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        marketplace_app = cls(
            id=id,
            name=name,
            description=description,
            category=category,
            version=version,
            author=author,
            icon_url=icon_url,
            config_schema=config_schema,
            required_scopes=required_scopes,
            install_count=install_count,
            rating=rating,
            org_id=org_id,
        )

        marketplace_app.additional_properties = d
        return marketplace_app

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
