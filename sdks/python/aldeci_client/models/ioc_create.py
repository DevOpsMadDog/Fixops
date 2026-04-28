from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IOCCreate")


@_attrs_define
class IOCCreate:
    """
    Attributes:
        ioc_type (str):
        value (str):
        context (str | Unset):  Default: ''.
        first_seen (None | str | Unset):
        last_seen (None | str | Unset):
        confidence (float | Unset):  Default: 0.5.
    """

    ioc_type: str
    value: str
    context: str | Unset = ""
    first_seen: None | str | Unset = UNSET
    last_seen: None | str | Unset = UNSET
    confidence: float | Unset = 0.5
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ioc_type = self.ioc_type

        value = self.value

        context = self.context

        first_seen: None | str | Unset
        if isinstance(self.first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = self.first_seen

        last_seen: None | str | Unset
        if isinstance(self.last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = self.last_seen

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ioc_type": ioc_type,
                "value": value,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ioc_type = d.pop("ioc_type")

        value = d.pop("value")

        context = d.pop("context", UNSET)

        def _parse_first_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        first_seen = _parse_first_seen(d.pop("first_seen", UNSET))

        def _parse_last_seen(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_seen = _parse_last_seen(d.pop("last_seen", UNSET))

        confidence = d.pop("confidence", UNSET)

        ioc_create = cls(
            ioc_type=ioc_type,
            value=value,
            context=context,
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=confidence,
        )

        ioc_create.additional_properties = d
        return ioc_create

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
