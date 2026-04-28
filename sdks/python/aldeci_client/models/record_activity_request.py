from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordActivityRequest")


@_attrs_define
class RecordActivityRequest:
    """
    Attributes:
        app_name (str): Cloud application name
        user (str): User identifier (email or username)
        activity_type (str): Activity type: upload/download/share/delete
        org_id (str | Unset): Organisation ID Default: 'default'.
        file_type (str | Unset): File MIME type or extension Default: ''.
        size_bytes (int | Unset): Size of data transferred in bytes Default: 0.
        destination (str | Unset): Destination: internal/external/public Default: 'internal'.
        data_classification (str | Unset): Data classification: public/internal/confidential/secret Default: 'internal'.
    """

    app_name: str
    user: str
    activity_type: str
    org_id: str | Unset = "default"
    file_type: str | Unset = ""
    size_bytes: int | Unset = 0
    destination: str | Unset = "internal"
    data_classification: str | Unset = "internal"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_name = self.app_name

        user = self.user

        activity_type = self.activity_type

        org_id = self.org_id

        file_type = self.file_type

        size_bytes = self.size_bytes

        destination = self.destination

        data_classification = self.data_classification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_name": app_name,
                "user": user,
                "activity_type": activity_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if file_type is not UNSET:
            field_dict["file_type"] = file_type
        if size_bytes is not UNSET:
            field_dict["size_bytes"] = size_bytes
        if destination is not UNSET:
            field_dict["destination"] = destination
        if data_classification is not UNSET:
            field_dict["data_classification"] = data_classification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_name = d.pop("app_name")

        user = d.pop("user")

        activity_type = d.pop("activity_type")

        org_id = d.pop("org_id", UNSET)

        file_type = d.pop("file_type", UNSET)

        size_bytes = d.pop("size_bytes", UNSET)

        destination = d.pop("destination", UNSET)

        data_classification = d.pop("data_classification", UNSET)

        record_activity_request = cls(
            app_name=app_name,
            user=user,
            activity_type=activity_type,
            org_id=org_id,
            file_type=file_type,
            size_bytes=size_bytes,
            destination=destination,
            data_classification=data_classification,
        )

        record_activity_request.additional_properties = d
        return record_activity_request

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
