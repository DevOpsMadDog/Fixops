from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProcessingActivityReq")


@_attrs_define
class ProcessingActivityReq:
    """
    Attributes:
        org_id (str):
        name (str):
        purpose (str):
        lawful_basis (str):
        data_categories (list[str] | Unset):
        recipients (list[str] | Unset):
        retention_period (None | str | Unset):
    """

    org_id: str
    name: str
    purpose: str
    lawful_basis: str
    data_categories: list[str] | Unset = UNSET
    recipients: list[str] | Unset = UNSET
    retention_period: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        name = self.name

        purpose = self.purpose

        lawful_basis = self.lawful_basis

        data_categories: list[str] | Unset = UNSET
        if not isinstance(self.data_categories, Unset):
            data_categories = self.data_categories

        recipients: list[str] | Unset = UNSET
        if not isinstance(self.recipients, Unset):
            recipients = self.recipients

        retention_period: None | str | Unset
        if isinstance(self.retention_period, Unset):
            retention_period = UNSET
        else:
            retention_period = self.retention_period

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "name": name,
                "purpose": purpose,
                "lawful_basis": lawful_basis,
            }
        )
        if data_categories is not UNSET:
            field_dict["data_categories"] = data_categories
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if retention_period is not UNSET:
            field_dict["retention_period"] = retention_period

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        name = d.pop("name")

        purpose = d.pop("purpose")

        lawful_basis = d.pop("lawful_basis")

        data_categories = cast(list[str], d.pop("data_categories", UNSET))

        recipients = cast(list[str], d.pop("recipients", UNSET))

        def _parse_retention_period(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        retention_period = _parse_retention_period(d.pop("retention_period", UNSET))

        processing_activity_req = cls(
            org_id=org_id,
            name=name,
            purpose=purpose,
            lawful_basis=lawful_basis,
            data_categories=data_categories,
            recipients=recipients,
            retention_period=retention_period,
        )

        processing_activity_req.additional_properties = d
        return processing_activity_req

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
