from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MaturityUpdate")


@_attrs_define
class MaturityUpdate:
    """
    Attributes:
        maturity_level (int):
        evidence (str | Unset):  Default: ''.
    """

    maturity_level: int
    evidence: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        maturity_level = self.maturity_level

        evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "maturity_level": maturity_level,
            }
        )
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        maturity_level = d.pop("maturity_level")

        evidence = d.pop("evidence", UNSET)

        maturity_update = cls(
            maturity_level=maturity_level,
            evidence=evidence,
        )

        maturity_update.additional_properties = d
        return maturity_update

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
