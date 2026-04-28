from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.add_context_request_data import AddContextRequestData


T = TypeVar("T", bound="AddContextRequest")


@_attrs_define
class AddContextRequest:
    """Request to add context to a session.

    Attributes:
        context_type (str): Type of context (cve, asset, finding)
        data (AddContextRequestData): Context data
    """

    context_type: str
    data: AddContextRequestData
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        context_type = self.context_type

        data = self.data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "context_type": context_type,
                "data": data,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_context_request_data import AddContextRequestData

        d = dict(src_dict)
        context_type = d.pop("context_type")

        data = AddContextRequestData.from_dict(d.pop("data"))

        add_context_request = cls(
            context_type=context_type,
            data=data,
        )

        add_context_request.additional_properties = d
        return add_context_request

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
