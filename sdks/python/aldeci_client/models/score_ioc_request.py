from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScoreIOCRequest")


@_attrs_define
class ScoreIOCRequest:
    """
    Attributes:
        ioc_value (str): The IOC value (IP, domain, hash, etc.)
        source_name (str): Name of the contributing source
        source_confidence (float): Source confidence for this IOC (0.0–1.0)
        org_id (str | Unset): Organisation identifier Default: 'default'.
        ioc_type (str | Unset): Type: ip/domain/url/hash/email/asn/cidr/user_agent Default: 'ip'.
    """

    ioc_value: str
    source_name: str
    source_confidence: float
    org_id: str | Unset = "default"
    ioc_type: str | Unset = "ip"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ioc_value = self.ioc_value

        source_name = self.source_name

        source_confidence = self.source_confidence

        org_id = self.org_id

        ioc_type = self.ioc_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ioc_value": ioc_value,
                "source_name": source_name,
                "source_confidence": source_confidence,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if ioc_type is not UNSET:
            field_dict["ioc_type"] = ioc_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ioc_value = d.pop("ioc_value")

        source_name = d.pop("source_name")

        source_confidence = d.pop("source_confidence")

        org_id = d.pop("org_id", UNSET)

        ioc_type = d.pop("ioc_type", UNSET)

        score_ioc_request = cls(
            ioc_value=ioc_value,
            source_name=source_name,
            source_confidence=source_confidence,
            org_id=org_id,
            ioc_type=ioc_type,
        )

        score_ioc_request.additional_properties = d
        return score_ioc_request

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
