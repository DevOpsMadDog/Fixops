from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.blocked_request_body_request_headers import BlockedRequestBodyRequestHeaders


T = TypeVar("T", bound="BlockedRequestBody")


@_attrs_define
class BlockedRequestBody:
    """
    Attributes:
        rule_id (str | Unset):  Default: ''.
        source_ip (str | Unset):  Default: ''.
        uri (str | Unset):  Default: ''.
        method (str | Unset):  Default: 'GET'.
        user_agent (str | Unset):  Default: ''.
        attack_type (str | Unset):  Default: 'xss'.
        severity (str | Unset):  Default: 'high'.
        request_headers (BlockedRequestBodyRequestHeaders | Unset):
        blocked_at (None | str | Unset):
    """

    rule_id: str | Unset = ""
    source_ip: str | Unset = ""
    uri: str | Unset = ""
    method: str | Unset = "GET"
    user_agent: str | Unset = ""
    attack_type: str | Unset = "xss"
    severity: str | Unset = "high"
    request_headers: BlockedRequestBodyRequestHeaders | Unset = UNSET
    blocked_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_id = self.rule_id

        source_ip = self.source_ip

        uri = self.uri

        method = self.method

        user_agent = self.user_agent

        attack_type = self.attack_type

        severity = self.severity

        request_headers: dict[str, Any] | Unset = UNSET
        if not isinstance(self.request_headers, Unset):
            request_headers = self.request_headers.to_dict()

        blocked_at: None | str | Unset
        if isinstance(self.blocked_at, Unset):
            blocked_at = UNSET
        else:
            blocked_at = self.blocked_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if uri is not UNSET:
            field_dict["uri"] = uri
        if method is not UNSET:
            field_dict["method"] = method
        if user_agent is not UNSET:
            field_dict["user_agent"] = user_agent
        if attack_type is not UNSET:
            field_dict["attack_type"] = attack_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if request_headers is not UNSET:
            field_dict["request_headers"] = request_headers
        if blocked_at is not UNSET:
            field_dict["blocked_at"] = blocked_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.blocked_request_body_request_headers import BlockedRequestBodyRequestHeaders

        d = dict(src_dict)
        rule_id = d.pop("rule_id", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        uri = d.pop("uri", UNSET)

        method = d.pop("method", UNSET)

        user_agent = d.pop("user_agent", UNSET)

        attack_type = d.pop("attack_type", UNSET)

        severity = d.pop("severity", UNSET)

        _request_headers = d.pop("request_headers", UNSET)
        request_headers: BlockedRequestBodyRequestHeaders | Unset
        if isinstance(_request_headers, Unset):
            request_headers = UNSET
        else:
            request_headers = BlockedRequestBodyRequestHeaders.from_dict(_request_headers)

        def _parse_blocked_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        blocked_at = _parse_blocked_at(d.pop("blocked_at", UNSET))

        blocked_request_body = cls(
            rule_id=rule_id,
            source_ip=source_ip,
            uri=uri,
            method=method,
            user_agent=user_agent,
            attack_type=attack_type,
            severity=severity,
            request_headers=request_headers,
            blocked_at=blocked_at,
        )

        blocked_request_body.additional_properties = d
        return blocked_request_body

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
