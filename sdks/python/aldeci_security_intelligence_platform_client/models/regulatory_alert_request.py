from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegulatoryAlertRequest")


@_attrs_define
class RegulatoryAlertRequest:
    """Request to check regulatory alerts.

    Attributes:
        jurisdictions (list[str] | Unset):
        industries (list[str] | Unset):
    """

    jurisdictions: list[str] | Unset = UNSET
    industries: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        jurisdictions: list[str] | Unset = UNSET
        if not isinstance(self.jurisdictions, Unset):
            jurisdictions = self.jurisdictions

        industries: list[str] | Unset = UNSET
        if not isinstance(self.industries, Unset):
            industries = self.industries

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if jurisdictions is not UNSET:
            field_dict["jurisdictions"] = jurisdictions
        if industries is not UNSET:
            field_dict["industries"] = industries

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        jurisdictions = cast(list[str], d.pop("jurisdictions", UNSET))

        industries = cast(list[str], d.pop("industries", UNSET))

        regulatory_alert_request = cls(
            jurisdictions=jurisdictions,
            industries=industries,
        )

        regulatory_alert_request.additional_properties = d
        return regulatory_alert_request

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
