from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.siem_forward_request_config_type_0 import SIEMForwardRequestConfigType0
    from ..models.siem_forward_request_event import SIEMForwardRequestEvent


T = TypeVar("T", bound="SIEMForwardRequest")


@_attrs_define
class SIEMForwardRequest:
    """
    Attributes:
        adapter (str):
        event (SIEMForwardRequestEvent | Unset):
        config (None | SIEMForwardRequestConfigType0 | Unset):
    """

    adapter: str
    event: SIEMForwardRequestEvent | Unset = UNSET
    config: None | SIEMForwardRequestConfigType0 | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.siem_forward_request_config_type_0 import SIEMForwardRequestConfigType0

        adapter = self.adapter

        event: dict[str, Any] | Unset = UNSET
        if not isinstance(self.event, Unset):
            event = self.event.to_dict()

        config: dict[str, Any] | None | Unset
        if isinstance(self.config, Unset):
            config = UNSET
        elif isinstance(self.config, SIEMForwardRequestConfigType0):
            config = self.config.to_dict()
        else:
            config = self.config

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "adapter": adapter,
            }
        )
        if event is not UNSET:
            field_dict["event"] = event
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.siem_forward_request_config_type_0 import SIEMForwardRequestConfigType0
        from ..models.siem_forward_request_event import SIEMForwardRequestEvent

        d = dict(src_dict)
        adapter = d.pop("adapter")

        _event = d.pop("event", UNSET)
        event: SIEMForwardRequestEvent | Unset
        if isinstance(_event, Unset):
            event = UNSET
        else:
            event = SIEMForwardRequestEvent.from_dict(_event)

        def _parse_config(data: object) -> None | SIEMForwardRequestConfigType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                config_type_0 = SIEMForwardRequestConfigType0.from_dict(data)

                return config_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SIEMForwardRequestConfigType0 | Unset, data)

        config = _parse_config(d.pop("config", UNSET))

        siem_forward_request = cls(
            adapter=adapter,
            event=event,
            config=config,
        )

        siem_forward_request.additional_properties = d
        return siem_forward_request

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
