from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.test_request_item_headers import TestRequestItemHeaders


T = TypeVar("T", bound="TestRequestItem")


@_attrs_define
class TestRequestItem:
    """
    Attributes:
        uri (str):
        method (str | Unset):  Default: 'GET'.
        query_string (str | Unset):  Default: ''.
        body (str | Unset):  Default: ''.
        headers (TestRequestItemHeaders | Unset):
        is_malicious (bool | Unset):  Default: False.
    """

    uri: str
    method: str | Unset = "GET"
    query_string: str | Unset = ""
    body: str | Unset = ""
    headers: TestRequestItemHeaders | Unset = UNSET
    is_malicious: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        uri = self.uri

        method = self.method

        query_string = self.query_string

        body = self.body

        headers: dict[str, Any] | Unset = UNSET
        if not isinstance(self.headers, Unset):
            headers = self.headers.to_dict()

        is_malicious = self.is_malicious

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "uri": uri,
            }
        )
        if method is not UNSET:
            field_dict["method"] = method
        if query_string is not UNSET:
            field_dict["query_string"] = query_string
        if body is not UNSET:
            field_dict["body"] = body
        if headers is not UNSET:
            field_dict["headers"] = headers
        if is_malicious is not UNSET:
            field_dict["is_malicious"] = is_malicious

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.test_request_item_headers import TestRequestItemHeaders

        d = dict(src_dict)
        uri = d.pop("uri")

        method = d.pop("method", UNSET)

        query_string = d.pop("query_string", UNSET)

        body = d.pop("body", UNSET)

        _headers = d.pop("headers", UNSET)
        headers: TestRequestItemHeaders | Unset
        if isinstance(_headers, Unset):
            headers = UNSET
        else:
            headers = TestRequestItemHeaders.from_dict(_headers)

        is_malicious = d.pop("is_malicious", UNSET)

        test_request_item = cls(
            uri=uri,
            method=method,
            query_string=query_string,
            body=body,
            headers=headers,
            is_malicious=is_malicious,
        )

        test_request_item.additional_properties = d
        return test_request_item

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
