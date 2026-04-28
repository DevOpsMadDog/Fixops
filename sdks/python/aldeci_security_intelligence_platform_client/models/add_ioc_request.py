from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddIocRequest")


@_attrs_define
class AddIocRequest:
    """
    Attributes:
        hunt_id (str): Associated hunt ID
        ioc_value (str): IOC value (hash, IP, domain, etc.)
        org_id (str | Unset): Organisation ID Default: 'default'.
        ioc_type (str | Unset): hash/ip/domain/path/registry_key/mutex/process_name/user_agent Default: 'hash'.
        confidence_score (float | Unset): Confidence 0-100 Default: 0.0.
        endpoints_matched (int | Unset): Number of endpoints matched Default: 0.
    """

    hunt_id: str
    ioc_value: str
    org_id: str | Unset = "default"
    ioc_type: str | Unset = "hash"
    confidence_score: float | Unset = 0.0
    endpoints_matched: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        hunt_id = self.hunt_id

        ioc_value = self.ioc_value

        org_id = self.org_id

        ioc_type = self.ioc_type

        confidence_score = self.confidence_score

        endpoints_matched = self.endpoints_matched

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "hunt_id": hunt_id,
                "ioc_value": ioc_value,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type
        if confidence_score is not UNSET:
            field_dict["confidence_score"] = confidence_score
        if endpoints_matched is not UNSET:
            field_dict["endpoints_matched"] = endpoints_matched

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        hunt_id = d.pop("hunt_id")

        ioc_value = d.pop("ioc_value")

        org_id = d.pop("org_id", UNSET)

        ioc_type = d.pop("ioc_type", UNSET)

        confidence_score = d.pop("confidence_score", UNSET)

        endpoints_matched = d.pop("endpoints_matched", UNSET)

        add_ioc_request = cls(
            hunt_id=hunt_id,
            ioc_value=ioc_value,
            org_id=org_id,
            ioc_type=ioc_type,
            confidence_score=confidence_score,
            endpoints_matched=endpoints_matched,
        )

        add_ioc_request.additional_properties = d
        return add_ioc_request

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
