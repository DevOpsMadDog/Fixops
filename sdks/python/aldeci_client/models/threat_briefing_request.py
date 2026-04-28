from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.threat_briefing_request_threat_context import ThreatBriefingRequestThreatContext


T = TypeVar("T", bound="ThreatBriefingRequest")


@_attrs_define
class ThreatBriefingRequest:
    """
    Attributes:
        threat_context (ThreatBriefingRequestThreatContext | Unset): Threat context: industry, active_campaigns,
            recent_iocs, threat_actor_ttps, etc.
    """

    threat_context: ThreatBriefingRequestThreatContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.threat_context, Unset):
            threat_context = self.threat_context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if threat_context is not UNSET:
            field_dict["threat_context"] = threat_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.threat_briefing_request_threat_context import ThreatBriefingRequestThreatContext

        d = dict(src_dict)
        _threat_context = d.pop("threat_context", UNSET)
        threat_context: ThreatBriefingRequestThreatContext | Unset
        if isinstance(_threat_context, Unset):
            threat_context = UNSET
        else:
            threat_context = ThreatBriefingRequestThreatContext.from_dict(_threat_context)

        threat_briefing_request = cls(
            threat_context=threat_context,
        )

        threat_briefing_request.additional_properties = d
        return threat_briefing_request

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
