from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ResourceStateUpdate")


@_attrs_define
class ResourceStateUpdate:
    """
    Attributes:
        state (str): running/stopped/terminated/unknown/pending
        compliance_status (None | str | Unset): compliant/non_compliant/unknown/exempt
    """

    state: str
    compliance_status: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        state = self.state

        compliance_status: None | str | Unset
        if isinstance(self.compliance_status, Unset):
            compliance_status = UNSET
        else:
            compliance_status = self.compliance_status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "state": state,
            }
        )
        if compliance_status is not UNSET:
            field_dict["compliance_status"] = compliance_status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        state = d.pop("state")

        def _parse_compliance_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        compliance_status = _parse_compliance_status(d.pop("compliance_status", UNSET))

        resource_state_update = cls(
            state=state,
            compliance_status=compliance_status,
        )

        resource_state_update.additional_properties = d
        return resource_state_update

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
