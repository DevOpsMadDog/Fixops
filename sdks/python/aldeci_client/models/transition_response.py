from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="TransitionResponse")


@_attrs_define
class TransitionResponse:
    """Response after a successful transition.

    Attributes:
        event_id (str):
        finding_id (str):
        from_stage (None | str):
        to_stage (str):
        changed_by (str):
        reason (str):
        timestamp (str):
        org_id (str):
    """

    event_id: str
    finding_id: str
    from_stage: None | str
    to_stage: str
    changed_by: str
    reason: str
    timestamp: str
    org_id: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_id = self.event_id

        finding_id = self.finding_id

        from_stage: None | str
        from_stage = self.from_stage

        to_stage = self.to_stage

        changed_by = self.changed_by

        reason = self.reason

        timestamp = self.timestamp

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_id": event_id,
                "finding_id": finding_id,
                "from_stage": from_stage,
                "to_stage": to_stage,
                "changed_by": changed_by,
                "reason": reason,
                "timestamp": timestamp,
                "org_id": org_id,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        event_id = d.pop("event_id")

        finding_id = d.pop("finding_id")

        def _parse_from_stage(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        from_stage = _parse_from_stage(d.pop("from_stage"))

        to_stage = d.pop("to_stage")

        changed_by = d.pop("changed_by")

        reason = d.pop("reason")

        timestamp = d.pop("timestamp")

        org_id = d.pop("org_id")

        transition_response = cls(
            event_id=event_id,
            finding_id=finding_id,
            from_stage=from_stage,
            to_stage=to_stage,
            changed_by=changed_by,
            reason=reason,
            timestamp=timestamp,
            org_id=org_id,
        )

        transition_response.additional_properties = d
        return transition_response

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
