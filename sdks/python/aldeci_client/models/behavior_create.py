from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.behavior_create_details import BehaviorCreateDetails


T = TypeVar("T", bound="BehaviorCreate")


@_attrs_define
class BehaviorCreate:
    """
    Attributes:
        user_id (str):
        behavior_type (str):
        risk_score (int | Unset):  Default: 50.
        details (BehaviorCreateDetails | Unset):
    """

    user_id: str
    behavior_type: str
    risk_score: int | Unset = 50
    details: BehaviorCreateDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        behavior_type = self.behavior_type

        risk_score = self.risk_score

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "behavior_type": behavior_type,
            }
        )
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.behavior_create_details import BehaviorCreateDetails

        d = dict(src_dict)
        user_id = d.pop("user_id")

        behavior_type = d.pop("behavior_type")

        risk_score = d.pop("risk_score", UNSET)

        _details = d.pop("details", UNSET)
        details: BehaviorCreateDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = BehaviorCreateDetails.from_dict(_details)

        behavior_create = cls(
            user_id=user_id,
            behavior_type=behavior_type,
            risk_score=risk_score,
            details=details,
        )

        behavior_create.additional_properties = d
        return behavior_create

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
