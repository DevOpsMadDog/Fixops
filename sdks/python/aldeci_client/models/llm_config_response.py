from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.llm_provider_status import LLMProviderStatus


T = TypeVar("T", bound="LLMConfigResponse")


@_attrs_define
class LLMConfigResponse:
    """Response for LLM configuration endpoint.

    Attributes:
        status (str):
        providers (list[LLMProviderStatus]):
        message (str):
        active_provider (None | str | Unset):
    """

    status: str
    providers: list[LLMProviderStatus]
    message: str
    active_provider: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status = self.status

        providers = []
        for providers_item_data in self.providers:
            providers_item = providers_item_data.to_dict()
            providers.append(providers_item)

        message = self.message

        active_provider: None | str | Unset
        if isinstance(self.active_provider, Unset):
            active_provider = UNSET
        else:
            active_provider = self.active_provider

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "providers": providers,
                "message": message,
            }
        )
        if active_provider is not UNSET:
            field_dict["active_provider"] = active_provider

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.llm_provider_status import LLMProviderStatus

        d = dict(src_dict)
        status = d.pop("status")

        providers = []
        _providers = d.pop("providers")
        for providers_item_data in _providers:
            providers_item = LLMProviderStatus.from_dict(providers_item_data)

            providers.append(providers_item)

        message = d.pop("message")

        def _parse_active_provider(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        active_provider = _parse_active_provider(d.pop("active_provider", UNSET))

        llm_config_response = cls(
            status=status,
            providers=providers,
            message=message,
            active_provider=active_provider,
        )

        llm_config_response.additional_properties = d
        return llm_config_response

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
