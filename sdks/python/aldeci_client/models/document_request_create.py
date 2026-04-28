from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DocumentRequestCreate")


@_attrs_define
class DocumentRequestCreate:
    """
    Attributes:
        request_type (str):
        requester_name (str):
        requester_email (str):
        requester_company (str):
        requester_title (None | str | Unset):
        message (None | str | Unset):
    """

    request_type: str
    requester_name: str
    requester_email: str
    requester_company: str
    requester_title: None | str | Unset = UNSET
    message: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        request_type = self.request_type

        requester_name = self.requester_name

        requester_email = self.requester_email

        requester_company = self.requester_company

        requester_title: None | str | Unset
        if isinstance(self.requester_title, Unset):
            requester_title = UNSET
        else:
            requester_title = self.requester_title

        message: None | str | Unset
        if isinstance(self.message, Unset):
            message = UNSET
        else:
            message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "request_type": request_type,
                "requester_name": requester_name,
                "requester_email": requester_email,
                "requester_company": requester_company,
            }
        )
        if requester_title is not UNSET:
            field_dict["requester_title"] = requester_title
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        request_type = d.pop("request_type")

        requester_name = d.pop("requester_name")

        requester_email = d.pop("requester_email")

        requester_company = d.pop("requester_company")

        def _parse_requester_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        requester_title = _parse_requester_title(d.pop("requester_title", UNSET))

        def _parse_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        message = _parse_message(d.pop("message", UNSET))

        document_request_create = cls(
            request_type=request_type,
            requester_name=requester_name,
            requester_email=requester_email,
            requester_company=requester_company,
            requester_title=requester_title,
            message=message,
        )

        document_request_create.additional_properties = d
        return document_request_create

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
