from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogEmailEventRequest")


@_attrs_define
class LogEmailEventRequest:
    """
    Attributes:
        sender (str):
        recipient (str):
        filter_result (str):
        subject (str | Unset):  Default: ''.
        rule_id (str | Unset):  Default: ''.
        threat_score (int | Unset):  Default: 0.
        processed_at (None | str | Unset):
    """

    sender: str
    recipient: str
    filter_result: str
    subject: str | Unset = ""
    rule_id: str | Unset = ""
    threat_score: int | Unset = 0
    processed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sender = self.sender

        recipient = self.recipient

        filter_result = self.filter_result

        subject = self.subject

        rule_id = self.rule_id

        threat_score = self.threat_score

        processed_at: None | str | Unset
        if isinstance(self.processed_at, Unset):
            processed_at = UNSET
        else:
            processed_at = self.processed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sender": sender,
                "recipient": recipient,
                "filter_result": filter_result,
            }
        )
        if subject is not UNSET:
            field_dict["subject"] = subject
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if threat_score is not UNSET:
            field_dict["threat_score"] = threat_score
        if processed_at is not UNSET:
            field_dict["processed_at"] = processed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sender = d.pop("sender")

        recipient = d.pop("recipient")

        filter_result = d.pop("filter_result")

        subject = d.pop("subject", UNSET)

        rule_id = d.pop("rule_id", UNSET)

        threat_score = d.pop("threat_score", UNSET)

        def _parse_processed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        processed_at = _parse_processed_at(d.pop("processed_at", UNSET))

        log_email_event_request = cls(
            sender=sender,
            recipient=recipient,
            filter_result=filter_result,
            subject=subject,
            rule_id=rule_id,
            threat_score=threat_score,
            processed_at=processed_at,
        )

        log_email_event_request.additional_properties = d
        return log_email_event_request

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
