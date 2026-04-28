from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateLevelRequest")


@_attrs_define
class UpdateLevelRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        maturity_level (int): New maturity level
        evidence (str | Unset): Updated evidence Default: ''.
    """

    org_id: str
    maturity_level: int
    evidence: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        maturity_level = self.maturity_level

        evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "maturity_level": maturity_level,
            }
        )
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        maturity_level = d.pop("maturity_level")

        evidence = d.pop("evidence", UNSET)

        update_level_request = cls(
            org_id=org_id,
            maturity_level=maturity_level,
            evidence=evidence,
        )

        update_level_request.additional_properties = d
        return update_level_request

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
