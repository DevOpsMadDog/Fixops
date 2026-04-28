from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.forward_event_request_metadata import ForwardEventRequestMetadata


T = TypeVar("T", bound="ForwardEventRequest")


@_attrs_define
class ForwardEventRequest:
    """
    Attributes:
        event_type (str): Event type identifier
        severity (str | Unset): critical, high, medium, low, info Default: 'info'.
        action (str | Unset): Action taken Default: ''.
        outcome (str | Unset): Outcome of the action Default: ''.
        message (str | Unset): Human-readable message Default: ''.
        src_ip (str | Unset):  Default: ''.
        dst_ip (str | Unset):  Default: ''.
        user_id (str | Unset):  Default: ''.
        app_id (str | Unset):  Default: ''.
        finding_id (str | Unset):  Default: ''.
        cve_id (str | Unset):  Default: ''.
        metadata (ForwardEventRequestMetadata | Unset):
    """

    event_type: str
    severity: str | Unset = "info"
    action: str | Unset = ""
    outcome: str | Unset = ""
    message: str | Unset = ""
    src_ip: str | Unset = ""
    dst_ip: str | Unset = ""
    user_id: str | Unset = ""
    app_id: str | Unset = ""
    finding_id: str | Unset = ""
    cve_id: str | Unset = ""
    metadata: ForwardEventRequestMetadata | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        event_type = self.event_type

        severity = self.severity

        action = self.action

        outcome = self.outcome

        message = self.message

        src_ip = self.src_ip

        dst_ip = self.dst_ip

        user_id = self.user_id

        app_id = self.app_id

        finding_id = self.finding_id

        cve_id = self.cve_id

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "event_type": event_type,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if action is not UNSET:
            field_dict["action"] = action
        if outcome is not UNSET:
            field_dict["outcome"] = outcome
        if message is not UNSET:
            field_dict["message"] = message
        if src_ip is not UNSET:
            field_dict["src_ip"] = src_ip
        if dst_ip is not UNSET:
            field_dict["dst_ip"] = dst_ip
        if user_id is not UNSET:
            field_dict["user_id"] = user_id
        if app_id is not UNSET:
            field_dict["app_id"] = app_id
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.forward_event_request_metadata import ForwardEventRequestMetadata

        d = dict(src_dict)
        event_type = d.pop("event_type")

        severity = d.pop("severity", UNSET)

        action = d.pop("action", UNSET)

        outcome = d.pop("outcome", UNSET)

        message = d.pop("message", UNSET)

        src_ip = d.pop("src_ip", UNSET)

        dst_ip = d.pop("dst_ip", UNSET)

        user_id = d.pop("user_id", UNSET)

        app_id = d.pop("app_id", UNSET)

        finding_id = d.pop("finding_id", UNSET)

        cve_id = d.pop("cve_id", UNSET)

        _metadata = d.pop("metadata", UNSET)
        metadata: ForwardEventRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = ForwardEventRequestMetadata.from_dict(_metadata)

        forward_event_request = cls(
            event_type=event_type,
            severity=severity,
            action=action,
            outcome=outcome,
            message=message,
            src_ip=src_ip,
            dst_ip=dst_ip,
            user_id=user_id,
            app_id=app_id,
            finding_id=finding_id,
            cve_id=cve_id,
            metadata=metadata,
        )

        forward_event_request.additional_properties = d
        return forward_event_request

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
