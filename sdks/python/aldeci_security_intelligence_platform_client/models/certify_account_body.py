from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CertifyAccountBody")


@_attrs_define
class CertifyAccountBody:
    """
    Attributes:
        certified_by (str): Certifier user ID
        decision (str): approved | revoked | suspended
        justification (str | Unset): Certification justification Default: ''.
        next_certification (str | Unset): Next certification date ISO Default: ''.
    """

    certified_by: str
    decision: str
    justification: str | Unset = ""
    next_certification: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        certified_by = self.certified_by

        decision = self.decision

        justification = self.justification

        next_certification = self.next_certification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "certified_by": certified_by,
                "decision": decision,
            }
        )
        if justification is not UNSET:
            field_dict["justification"] = justification
        if next_certification is not UNSET:
            field_dict["next_certification"] = next_certification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        certified_by = d.pop("certified_by")

        decision = d.pop("decision")

        justification = d.pop("justification", UNSET)

        next_certification = d.pop("next_certification", UNSET)

        certify_account_body = cls(
            certified_by=certified_by,
            decision=decision,
            justification=justification,
            next_certification=next_certification,
        )

        certify_account_body.additional_properties = d
        return certify_account_body

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
