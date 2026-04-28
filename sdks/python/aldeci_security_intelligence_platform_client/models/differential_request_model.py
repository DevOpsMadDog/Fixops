from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.differential_request_model_headers import DifferentialRequestModelHeaders


T = TypeVar("T", bound="DifferentialRequestModel")


@_attrs_define
class DifferentialRequestModel:
    """
    Attributes:
        method (str | Unset):  Default: 'GET'.
        path (str | Unset):  Default: '/'.
        headers (DifferentialRequestModelHeaders | Unset):
        body (None | str | Unset):
    """

    method: str | Unset = "GET"
    path: str | Unset = "/"
    headers: DifferentialRequestModelHeaders | Unset = UNSET
    body: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        method = self.method

        path = self.path

        headers: dict[str, Any] | Unset = UNSET
        if not isinstance(self.headers, Unset):
            headers = self.headers.to_dict()

        body: None | str | Unset
        if isinstance(self.body, Unset):
            body = UNSET
        else:
            body = self.body

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if method is not UNSET:
            field_dict["method"] = method
        if path is not UNSET:
            field_dict["path"] = path
        if headers is not UNSET:
            field_dict["headers"] = headers
        if body is not UNSET:
            field_dict["body"] = body

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.differential_request_model_headers import DifferentialRequestModelHeaders

        d = dict(src_dict)
        method = d.pop("method", UNSET)

        path = d.pop("path", UNSET)

        _headers = d.pop("headers", UNSET)
        headers: DifferentialRequestModelHeaders | Unset
        if isinstance(_headers, Unset):
            headers = UNSET
        else:
            headers = DifferentialRequestModelHeaders.from_dict(_headers)

        def _parse_body(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        body = _parse_body(d.pop("body", UNSET))

        differential_request_model = cls(
            method=method,
            path=path,
            headers=headers,
            body=body,
        )

        differential_request_model.additional_properties = d
        return differential_request_model

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
