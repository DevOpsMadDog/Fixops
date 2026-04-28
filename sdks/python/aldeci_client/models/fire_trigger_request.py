from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.hunt_trigger_type import HuntTriggerType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.fire_trigger_request_context import FireTriggerRequestContext


T = TypeVar("T", bound="FireTriggerRequest")


@_attrs_define
class FireTriggerRequest:
    """Body for firing an automated hunt trigger.

    Attributes:
        trigger_type (HuntTriggerType):
        context (FireTriggerRequestContext | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    trigger_type: HuntTriggerType
    context: FireTriggerRequestContext | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        trigger_type = self.trigger_type.value

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "trigger_type": trigger_type,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fire_trigger_request_context import FireTriggerRequestContext

        d = dict(src_dict)
        trigger_type = HuntTriggerType(d.pop("trigger_type"))

        _context = d.pop("context", UNSET)
        context: FireTriggerRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = FireTriggerRequestContext.from_dict(_context)

        org_id = d.pop("org_id", UNSET)

        fire_trigger_request = cls(
            trigger_type=trigger_type,
            context=context,
            org_id=org_id,
        )

        fire_trigger_request.additional_properties = d
        return fire_trigger_request

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
