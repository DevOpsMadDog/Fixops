from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.plan_tier import PlanTier
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.gateway_check_request_payload_dict_type_0 import GatewayCheckRequestPayloadDictType0


T = TypeVar("T", bound="GatewayCheckRequest")


@_attrs_define
class GatewayCheckRequest:
    """
    Attributes:
        endpoint (str): API endpoint path being requested
        ip (str): Client IP address
        method (str | Unset): HTTP method Default: 'GET'.
        content_type (None | str | Unset): Content-Type header value
        payload_size_bytes (int | Unset): Request body size in bytes Default: 0.
        api_key_id (None | str | Unset): API key ID for the request
        org_id (None | str | Unset): Organisation ID
        api_version (str | Unset): API version requested Default: 'v1'.
        plan_tier (PlanTier | Unset):
        required_fields (list[str] | None | Unset): Fields to validate in payload
        payload_dict (GatewayCheckRequestPayloadDictType0 | None | Unset): Parsed request body
    """

    endpoint: str
    ip: str
    method: str | Unset = "GET"
    content_type: None | str | Unset = UNSET
    payload_size_bytes: int | Unset = 0
    api_key_id: None | str | Unset = UNSET
    org_id: None | str | Unset = UNSET
    api_version: str | Unset = "v1"
    plan_tier: PlanTier | Unset = UNSET
    required_fields: list[str] | None | Unset = UNSET
    payload_dict: GatewayCheckRequestPayloadDictType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.gateway_check_request_payload_dict_type_0 import GatewayCheckRequestPayloadDictType0

        endpoint = self.endpoint

        ip = self.ip

        method = self.method

        content_type: None | str | Unset
        if isinstance(self.content_type, Unset):
            content_type = UNSET
        else:
            content_type = self.content_type

        payload_size_bytes = self.payload_size_bytes

        api_key_id: None | str | Unset
        if isinstance(self.api_key_id, Unset):
            api_key_id = UNSET
        else:
            api_key_id = self.api_key_id

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        api_version = self.api_version

        plan_tier: str | Unset = UNSET
        if not isinstance(self.plan_tier, Unset):
            plan_tier = self.plan_tier.value

        required_fields: list[str] | None | Unset
        if isinstance(self.required_fields, Unset):
            required_fields = UNSET
        elif isinstance(self.required_fields, list):
            required_fields = self.required_fields

        else:
            required_fields = self.required_fields

        payload_dict: dict[str, Any] | None | Unset
        if isinstance(self.payload_dict, Unset):
            payload_dict = UNSET
        elif isinstance(self.payload_dict, GatewayCheckRequestPayloadDictType0):
            payload_dict = self.payload_dict.to_dict()
        else:
            payload_dict = self.payload_dict

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "endpoint": endpoint,
                "ip": ip,
            }
        )
        if method is not UNSET:
            field_dict["method"] = method
        if content_type is not UNSET:
            field_dict["content_type"] = content_type
        if payload_size_bytes is not UNSET:
            field_dict["payload_size_bytes"] = payload_size_bytes
        if api_key_id is not UNSET:
            field_dict["api_key_id"] = api_key_id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if api_version is not UNSET:
            field_dict["api_version"] = api_version
        if plan_tier is not UNSET:
            field_dict["plan_tier"] = plan_tier
        if required_fields is not UNSET:
            field_dict["required_fields"] = required_fields
        if payload_dict is not UNSET:
            field_dict["payload_dict"] = payload_dict

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gateway_check_request_payload_dict_type_0 import GatewayCheckRequestPayloadDictType0

        d = dict(src_dict)
        endpoint = d.pop("endpoint")

        ip = d.pop("ip")

        method = d.pop("method", UNSET)

        def _parse_content_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        content_type = _parse_content_type(d.pop("content_type", UNSET))

        payload_size_bytes = d.pop("payload_size_bytes", UNSET)

        def _parse_api_key_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_key_id = _parse_api_key_id(d.pop("api_key_id", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        api_version = d.pop("api_version", UNSET)

        _plan_tier = d.pop("plan_tier", UNSET)
        plan_tier: PlanTier | Unset
        if isinstance(_plan_tier, Unset):
            plan_tier = UNSET
        else:
            plan_tier = PlanTier(_plan_tier)

        def _parse_required_fields(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                required_fields_type_0 = cast(list[str], data)

                return required_fields_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        required_fields = _parse_required_fields(d.pop("required_fields", UNSET))

        def _parse_payload_dict(data: object) -> GatewayCheckRequestPayloadDictType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                payload_dict_type_0 = GatewayCheckRequestPayloadDictType0.from_dict(data)

                return payload_dict_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GatewayCheckRequestPayloadDictType0 | None | Unset, data)

        payload_dict = _parse_payload_dict(d.pop("payload_dict", UNSET))

        gateway_check_request = cls(
            endpoint=endpoint,
            ip=ip,
            method=method,
            content_type=content_type,
            payload_size_bytes=payload_size_bytes,
            api_key_id=api_key_id,
            org_id=org_id,
            api_version=api_version,
            plan_tier=plan_tier,
            required_fields=required_fields,
            payload_dict=payload_dict,
        )

        gateway_check_request.additional_properties = d
        return gateway_check_request

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
