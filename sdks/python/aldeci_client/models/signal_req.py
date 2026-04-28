from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SignalReq")


@_attrs_define
class SignalReq:
    """
    Attributes:
        package_purl (str):
        signal_type (str):
        org_id (str | Unset):  Default: 'default'.
        value (Any | Unset):  Default: ''.
        evidence_uri (str | Unset):  Default: ''.
    """

    package_purl: str
    signal_type: str
    org_id: str | Unset = "default"
    value: Any | Unset = ""
    evidence_uri: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_purl = self.package_purl

        signal_type = self.signal_type

        org_id = self.org_id

        value = self.value

        evidence_uri = self.evidence_uri

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_purl": package_purl,
                "signal_type": signal_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if value is not UNSET:
            field_dict["value"] = value
        if evidence_uri is not UNSET:
            field_dict["evidence_uri"] = evidence_uri

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        package_purl = d.pop("package_purl")

        signal_type = d.pop("signal_type")

        org_id = d.pop("org_id", UNSET)

        value = d.pop("value", UNSET)

        evidence_uri = d.pop("evidence_uri", UNSET)

        signal_req = cls(
            package_purl=package_purl,
            signal_type=signal_type,
            org_id=org_id,
            value=value,
            evidence_uri=evidence_uri,
        )

        signal_req.additional_properties = d
        return signal_req

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
