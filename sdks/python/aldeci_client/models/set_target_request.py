from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SetTargetRequest")


@_attrs_define
class SetTargetRequest:
    """
    Attributes:
        domain_name (str): Domain name to set target for
        target_score (float): Target score to achieve
        current_score (float): Current score baseline
        deadline (str): Target deadline (YYYY-MM-DD)
        owner (str | Unset): Owner responsible for achieving target Default: ''.
    """

    domain_name: str
    target_score: float
    current_score: float
    deadline: str
    owner: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        domain_name = self.domain_name

        target_score = self.target_score

        current_score = self.current_score

        deadline = self.deadline

        owner = self.owner

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "domain_name": domain_name,
                "target_score": target_score,
                "current_score": current_score,
                "deadline": deadline,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        domain_name = d.pop("domain_name")

        target_score = d.pop("target_score")

        current_score = d.pop("current_score")

        deadline = d.pop("deadline")

        owner = d.pop("owner", UNSET)

        set_target_request = cls(
            domain_name=domain_name,
            target_score=target_score,
            current_score=current_score,
            deadline=deadline,
            owner=owner,
        )

        set_target_request.additional_properties = d
        return set_target_request

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
