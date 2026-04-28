from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rasp_mode import RaspMode
from ..types import UNSET, Unset

T = TypeVar("T", bound="SetModeRequest")


@_attrs_define
class SetModeRequest:
    """Body for switching RASP operating mode.

    Attributes:
        mode (RaspMode): Operating mode for the RASP engine.
        honeypot_url (None | str | Unset): Honeypot redirect URL (required when mode=redirect)
    """

    mode: RaspMode
    honeypot_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mode = self.mode.value

        honeypot_url: None | str | Unset
        if isinstance(self.honeypot_url, Unset):
            honeypot_url = UNSET
        else:
            honeypot_url = self.honeypot_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "mode": mode,
            }
        )
        if honeypot_url is not UNSET:
            field_dict["honeypot_url"] = honeypot_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        mode = RaspMode(d.pop("mode"))

        def _parse_honeypot_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        honeypot_url = _parse_honeypot_url(d.pop("honeypot_url", UNSET))

        set_mode_request = cls(
            mode=mode,
            honeypot_url=honeypot_url,
        )

        set_mode_request.additional_properties = d
        return set_mode_request

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
