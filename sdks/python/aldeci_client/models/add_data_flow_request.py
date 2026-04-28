from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddDataFlowRequest")


@_attrs_define
class AddDataFlowRequest:
    """
    Attributes:
        source_asset_id (str | Unset):  Default: ''.
        destination (str | Unset):  Default: ''.
        flow_type (str | Unset):  Default: 'internal'.
        data_categories (list[str] | Unset):
        encrypted (bool | Unset):  Default: False.
        approved (bool | Unset):  Default: False.
    """

    source_asset_id: str | Unset = ""
    destination: str | Unset = ""
    flow_type: str | Unset = "internal"
    data_categories: list[str] | Unset = UNSET
    encrypted: bool | Unset = False
    approved: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_asset_id = self.source_asset_id

        destination = self.destination

        flow_type = self.flow_type

        data_categories: list[str] | Unset = UNSET
        if not isinstance(self.data_categories, Unset):
            data_categories = self.data_categories

        encrypted = self.encrypted

        approved = self.approved

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if source_asset_id is not UNSET:
            field_dict["source_asset_id"] = source_asset_id
        if destination is not UNSET:
            field_dict["destination"] = destination
        if flow_type is not UNSET:
            field_dict["flow_type"] = flow_type
        if data_categories is not UNSET:
            field_dict["data_categories"] = data_categories
        if encrypted is not UNSET:
            field_dict["encrypted"] = encrypted
        if approved is not UNSET:
            field_dict["approved"] = approved

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        source_asset_id = d.pop("source_asset_id", UNSET)

        destination = d.pop("destination", UNSET)

        flow_type = d.pop("flow_type", UNSET)

        data_categories = cast(list[str], d.pop("data_categories", UNSET))

        encrypted = d.pop("encrypted", UNSET)

        approved = d.pop("approved", UNSET)

        add_data_flow_request = cls(
            source_asset_id=source_asset_id,
            destination=destination,
            flow_type=flow_type,
            data_categories=data_categories,
            encrypted=encrypted,
            approved=approved,
        )

        add_data_flow_request.additional_properties = d
        return add_data_flow_request

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
