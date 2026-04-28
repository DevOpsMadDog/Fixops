from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BodySsoCallbackApiV1AuthSsoProviderCallbackGet")


@_attrs_define
class BodySsoCallbackApiV1AuthSsoProviderCallbackGet:
    """
    Attributes:
        saml_response (None | str | Unset):
        relay_state (None | str | Unset):
    """

    saml_response: None | str | Unset = UNSET
    relay_state: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        saml_response: None | str | Unset
        if isinstance(self.saml_response, Unset):
            saml_response = UNSET
        else:
            saml_response = self.saml_response

        relay_state: None | str | Unset
        if isinstance(self.relay_state, Unset):
            relay_state = UNSET
        else:
            relay_state = self.relay_state

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if saml_response is not UNSET:
            field_dict["SAMLResponse"] = saml_response
        if relay_state is not UNSET:
            field_dict["RelayState"] = relay_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_saml_response(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        saml_response = _parse_saml_response(d.pop("SAMLResponse", UNSET))

        def _parse_relay_state(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        relay_state = _parse_relay_state(d.pop("RelayState", UNSET))

        body_sso_callback_api_v1_auth_sso_provider_callback_get = cls(
            saml_response=saml_response,
            relay_state=relay_state,
        )

        body_sso_callback_api_v1_auth_sso_provider_callback_get.additional_properties = d
        return body_sso_callback_api_v1_auth_sso_provider_callback_get

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
