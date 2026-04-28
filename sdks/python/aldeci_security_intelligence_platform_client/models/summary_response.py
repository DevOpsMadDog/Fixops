from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.summary_response_by_policy import SummaryResponseByPolicy
    from ..models.summary_response_by_risk import SummaryResponseByRisk


T = TypeVar("T", bound="SummaryResponse")


@_attrs_define
class SummaryResponse:
    """
    Attributes:
        org_id (str):
        total (int):
        by_risk (SummaryResponseByRisk):
        by_policy (SummaryResponseByPolicy):
        generated_at (str):
    """

    org_id: str
    total: int
    by_risk: SummaryResponseByRisk
    by_policy: SummaryResponseByPolicy
    generated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total = self.total

        by_risk = self.by_risk.to_dict()

        by_policy = self.by_policy.to_dict()

        generated_at = self.generated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total": total,
                "by_risk": by_risk,
                "by_policy": by_policy,
                "generated_at": generated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.summary_response_by_policy import SummaryResponseByPolicy
        from ..models.summary_response_by_risk import SummaryResponseByRisk

        d = dict(src_dict)
        org_id = d.pop("org_id")

        total = d.pop("total")

        by_risk = SummaryResponseByRisk.from_dict(d.pop("by_risk"))

        by_policy = SummaryResponseByPolicy.from_dict(d.pop("by_policy"))

        generated_at = d.pop("generated_at")

        summary_response = cls(
            org_id=org_id,
            total=total,
            by_risk=by_risk,
            by_policy=by_policy,
            generated_at=generated_at,
        )

        summary_response.additional_properties = d
        return summary_response

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
