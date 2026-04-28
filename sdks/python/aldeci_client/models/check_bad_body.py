from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CheckBadBody")


@_attrs_define
class CheckBadBody:
    """
    Attributes:
        blob_base64 (str): Base64-encoded binary blob
        org_id (None | str | Unset):
        candidate_id (str | Unset):  Default: ''.
    """

    blob_base64: str
    org_id: None | str | Unset = UNSET
    candidate_id: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        blob_base64 = self.blob_base64

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        candidate_id = self.candidate_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "blob_base64": blob_base64,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if candidate_id is not UNSET:
            field_dict["candidate_id"] = candidate_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        blob_base64 = d.pop("blob_base64")

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        candidate_id = d.pop("candidate_id", UNSET)

        check_bad_body = cls(
            blob_base64=blob_base64,
            org_id=org_id,
            candidate_id=candidate_id,
        )

        check_bad_body.additional_properties = d
        return check_bad_body

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
