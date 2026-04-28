from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RemediationTrigger")


@_attrs_define
class RemediationTrigger:
    """
    Attributes:
        finding_ids (list[str]):
        action (str): block | quarantine | patch | escalate | notify
        override_confidence (float | None | Unset):
        reason (None | str | Unset):
    """

    finding_ids: list[str]
    action: str
    override_confidence: float | None | Unset = UNSET
    reason: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_ids = self.finding_ids

        action = self.action

        override_confidence: float | None | Unset
        if isinstance(self.override_confidence, Unset):
            override_confidence = UNSET
        else:
            override_confidence = self.override_confidence

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_ids": finding_ids,
                "action": action,
            }
        )
        if override_confidence is not UNSET:
            field_dict["override_confidence"] = override_confidence
        if reason is not UNSET:
            field_dict["reason"] = reason

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_ids = cast(list[str], d.pop("finding_ids"))

        action = d.pop("action")

        def _parse_override_confidence(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        override_confidence = _parse_override_confidence(d.pop("override_confidence", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        remediation_trigger = cls(
            finding_ids=finding_ids,
            action=action,
            override_confidence=override_confidence,
            reason=reason,
        )

        remediation_trigger.additional_properties = d
        return remediation_trigger

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
