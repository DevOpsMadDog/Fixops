from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.trigger_alert_request_context_type_0 import TriggerAlertRequestContextType0


T = TypeVar("T", bound="TriggerAlertRequest")


@_attrs_define
class TriggerAlertRequest:
    """
    Attributes:
        title (str): Short alert title
        message (str): Detailed alert message
        policy_id (None | str | Unset): Originating policy ID
        source_engine (None | str | Unset): Engine that raised the alert
        source_id (None | str | Unset): Source record ID
        severity (str | Unset): critical | high | medium | low Default: 'medium'.
        context (None | TriggerAlertRequestContextType0 | Unset): Additional key-value context
    """

    title: str
    message: str
    policy_id: None | str | Unset = UNSET
    source_engine: None | str | Unset = UNSET
    source_id: None | str | Unset = UNSET
    severity: str | Unset = "medium"
    context: None | TriggerAlertRequestContextType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.trigger_alert_request_context_type_0 import TriggerAlertRequestContextType0

        title = self.title

        message = self.message

        policy_id: None | str | Unset
        if isinstance(self.policy_id, Unset):
            policy_id = UNSET
        else:
            policy_id = self.policy_id

        source_engine: None | str | Unset
        if isinstance(self.source_engine, Unset):
            source_engine = UNSET
        else:
            source_engine = self.source_engine

        source_id: None | str | Unset
        if isinstance(self.source_id, Unset):
            source_id = UNSET
        else:
            source_id = self.source_id

        severity = self.severity

        context: dict[str, Any] | None | Unset
        if isinstance(self.context, Unset):
            context = UNSET
        elif isinstance(self.context, TriggerAlertRequestContextType0):
            context = self.context.to_dict()
        else:
            context = self.context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "message": message,
            }
        )
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if source_engine is not UNSET:
            field_dict["source_engine"] = source_engine
        if source_id is not UNSET:
            field_dict["source_id"] = source_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.trigger_alert_request_context_type_0 import TriggerAlertRequestContextType0

        d = dict(src_dict)
        title = d.pop("title")

        message = d.pop("message")

        def _parse_policy_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_id = _parse_policy_id(d.pop("policy_id", UNSET))

        def _parse_source_engine(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_engine = _parse_source_engine(d.pop("source_engine", UNSET))

        def _parse_source_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_id = _parse_source_id(d.pop("source_id", UNSET))

        severity = d.pop("severity", UNSET)

        def _parse_context(data: object) -> None | TriggerAlertRequestContextType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                context_type_0 = TriggerAlertRequestContextType0.from_dict(data)

                return context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | TriggerAlertRequestContextType0 | Unset, data)

        context = _parse_context(d.pop("context", UNSET))

        trigger_alert_request = cls(
            title=title,
            message=message,
            policy_id=policy_id,
            source_engine=source_engine,
            source_id=source_id,
            severity=severity,
            context=context,
        )

        trigger_alert_request.additional_properties = d
        return trigger_alert_request

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
