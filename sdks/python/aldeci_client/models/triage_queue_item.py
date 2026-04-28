from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TriageQueueItem")


@_attrs_define
class TriageQueueItem:
    """A single item in the smart triage queue.

    Attributes:
        finding_id (str):
        title (str):
        severity (str):
        priority_score (float):
        sla_deadline (str):
        sla_urgency (float):
        bucket (str):
        attack_path_count (int | Unset):  Default: 0.
    """

    finding_id: str
    title: str
    severity: str
    priority_score: float
    sla_deadline: str
    sla_urgency: float
    bucket: str
    attack_path_count: int | Unset = 0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        title = self.title

        severity = self.severity

        priority_score = self.priority_score

        sla_deadline = self.sla_deadline

        sla_urgency = self.sla_urgency

        bucket = self.bucket

        attack_path_count = self.attack_path_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "title": title,
                "severity": severity,
                "priority_score": priority_score,
                "sla_deadline": sla_deadline,
                "sla_urgency": sla_urgency,
                "bucket": bucket,
            }
        )
        if attack_path_count is not UNSET:
            field_dict["attack_path_count"] = attack_path_count

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        title = d.pop("title")

        severity = d.pop("severity")

        priority_score = d.pop("priority_score")

        sla_deadline = d.pop("sla_deadline")

        sla_urgency = d.pop("sla_urgency")

        bucket = d.pop("bucket")

        attack_path_count = d.pop("attack_path_count", UNSET)

        triage_queue_item = cls(
            finding_id=finding_id,
            title=title,
            severity=severity,
            priority_score=priority_score,
            sla_deadline=sla_deadline,
            sla_urgency=sla_urgency,
            bucket=bucket,
            attack_path_count=attack_path_count,
        )

        triage_queue_item.additional_properties = d
        return triage_queue_item

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
