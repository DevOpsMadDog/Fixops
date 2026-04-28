from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CertifyRequest")


@_attrs_define
class CertifyRequest:
    """Body for submitting a certification decision.

    Attributes:
        decision (str): One of: 'certify', 'revoke', 'escalate'
        justification (str | Unset): Free-text reason for the decision Default: ''.
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    decision: str
    justification: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        decision = self.decision

        justification = self.justification

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "decision": decision,
            }
        )
        if justification is not UNSET:
            field_dict["justification"] = justification
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        decision = d.pop("decision")

        justification = d.pop("justification", UNSET)

        org_id = d.pop("org_id", UNSET)

        certify_request = cls(
            decision=decision,
            justification=justification,
            org_id=org_id,
        )

        certify_request.additional_properties = d
        return certify_request

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
