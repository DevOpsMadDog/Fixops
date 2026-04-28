from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.inspect_request_headers import InspectRequestHeaders


T = TypeVar("T", bound="InspectRequest")


@_attrs_define
class InspectRequest:
    """
    Attributes:
        source_ip (str): Client IP address
        path (str): Request path
        method (str | Unset): HTTP method Default: 'GET'.
        headers (InspectRequestHeaders | Unset):
        body (None | str | Unset):
        user_id (None | str | Unset):
    """

    source_ip: str
    path: str
    method: str | Unset = "GET"
    headers: InspectRequestHeaders | Unset = UNSET
    body: None | str | Unset = UNSET
    user_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_ip = self.source_ip

        path = self.path

        method = self.method

        headers: dict[str, Any] | Unset = UNSET
        if not isinstance(self.headers, Unset):
            headers = self.headers.to_dict()

        body: None | str | Unset
        if isinstance(self.body, Unset):
            body = UNSET
        else:
            body = self.body

        user_id: None | str | Unset
        if isinstance(self.user_id, Unset):
            user_id = UNSET
        else:
            user_id = self.user_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_ip": source_ip,
                "path": path,
            }
        )
        if method is not UNSET:
            field_dict["method"] = method
        if headers is not UNSET:
            field_dict["headers"] = headers
        if body is not UNSET:
            field_dict["body"] = body
        if user_id is not UNSET:
            field_dict["user_id"] = user_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.inspect_request_headers import InspectRequestHeaders

        d = dict(src_dict)
        source_ip = d.pop("source_ip")

        path = d.pop("path")

        method = d.pop("method", UNSET)

        _headers = d.pop("headers", UNSET)
        headers: InspectRequestHeaders | Unset
        if isinstance(_headers, Unset):
            headers = UNSET
        else:
            headers = InspectRequestHeaders.from_dict(_headers)

        def _parse_body(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        body = _parse_body(d.pop("body", UNSET))

        def _parse_user_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        user_id = _parse_user_id(d.pop("user_id", UNSET))

        inspect_request = cls(
            source_ip=source_ip,
            path=path,
            method=method,
            headers=headers,
            body=body,
            user_id=user_id,
        )

        inspect_request.additional_properties = d
        return inspect_request

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
