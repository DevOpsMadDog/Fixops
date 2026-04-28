from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.score_request import ScoreRequest


T = TypeVar("T", bound="PlanCreateRequest")


@_attrs_define
class PlanCreateRequest:
    """
    Attributes:
        cves (list[ScoreRequest]):
        org_id (str | Unset): Organisation ID Default: 'default'.
        plan_name (str | Unset): Human-readable plan name Default: 'Patch Plan'.
    """

    cves: list[ScoreRequest]
    org_id: str | Unset = "default"
    plan_name: str | Unset = "Patch Plan"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cves = []
        for cves_item_data in self.cves:
            cves_item = cves_item_data.to_dict()
            cves.append(cves_item)

        org_id = self.org_id

        plan_name = self.plan_name

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cves": cves,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if plan_name is not UNSET:
            field_dict["plan_name"] = plan_name

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.score_request import ScoreRequest

        d = dict(src_dict)
        cves = []
        _cves = d.pop("cves")
        for cves_item_data in _cves:
            cves_item = ScoreRequest.from_dict(cves_item_data)

            cves.append(cves_item)

        org_id = d.pop("org_id", UNSET)

        plan_name = d.pop("plan_name", UNSET)

        plan_create_request = cls(
            cves=cves,
            org_id=org_id,
            plan_name=plan_name,
        )

        plan_create_request.additional_properties = d
        return plan_create_request

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
