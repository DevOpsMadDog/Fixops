from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BaselineSet")


@_attrs_define
class BaselineSet:
    """
    Attributes:
        domain (str):
        baseline_score (float):
        target_score (float):
        set_by (str | Unset):  Default: ''.
    """

    domain: str
    baseline_score: float
    target_score: float
    set_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain = self.domain

        baseline_score = self.baseline_score

        target_score = self.target_score

        set_by = self.set_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain": domain,
                "baseline_score": baseline_score,
                "target_score": target_score,
            }
        )
        if set_by is not UNSET:
            field_dict["set_by"] = set_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain = d.pop("domain")

        baseline_score = d.pop("baseline_score")

        target_score = d.pop("target_score")

        set_by = d.pop("set_by", UNSET)

        baseline_set = cls(
            domain=domain,
            baseline_score=baseline_score,
            target_score=target_score,
            set_by=set_by,
        )

        baseline_set.additional_properties = d
        return baseline_set

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
