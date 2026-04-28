from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ProcessingActivityCreate")


@_attrs_define
class ProcessingActivityCreate:
    """
    Attributes:
        activity_name (str):
        purpose (str | Unset):  Default: ''.
        legal_basis (str | Unset):  Default: 'consent'.
        data_categories (list[str] | Unset):
        data_subjects (list[str] | Unset):
        retention_period_days (int | Unset):  Default: 365.
        third_party_recipients (list[str] | Unset):
        international_transfers (list[str] | Unset):
        dpiad_required (bool | Unset):  Default: False.
    """

    activity_name: str
    purpose: str | Unset = ""
    legal_basis: str | Unset = "consent"
    data_categories: list[str] | Unset = UNSET
    data_subjects: list[str] | Unset = UNSET
    retention_period_days: int | Unset = 365
    third_party_recipients: list[str] | Unset = UNSET
    international_transfers: list[str] | Unset = UNSET
    dpiad_required: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        activity_name = self.activity_name

        purpose = self.purpose

        legal_basis = self.legal_basis

        data_categories: list[str] | Unset = UNSET
        if not isinstance(self.data_categories, Unset):
            data_categories = self.data_categories

        data_subjects: list[str] | Unset = UNSET
        if not isinstance(self.data_subjects, Unset):
            data_subjects = self.data_subjects

        retention_period_days = self.retention_period_days

        third_party_recipients: list[str] | Unset = UNSET
        if not isinstance(self.third_party_recipients, Unset):
            third_party_recipients = self.third_party_recipients

        international_transfers: list[str] | Unset = UNSET
        if not isinstance(self.international_transfers, Unset):
            international_transfers = self.international_transfers

        dpiad_required = self.dpiad_required

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "activity_name": activity_name,
            }
        )
        if purpose is not UNSET:
            field_dict["purpose"] = purpose
        if legal_basis is not UNSET:
            field_dict["legal_basis"] = legal_basis
        if data_categories is not UNSET:
            field_dict["data_categories"] = data_categories
        if data_subjects is not UNSET:
            field_dict["data_subjects"] = data_subjects
        if retention_period_days is not UNSET:
            field_dict["retention_period_days"] = retention_period_days
        if third_party_recipients is not UNSET:
            field_dict["third_party_recipients"] = third_party_recipients
        if international_transfers is not UNSET:
            field_dict["international_transfers"] = international_transfers
        if dpiad_required is not UNSET:
            field_dict["dpiad_required"] = dpiad_required

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        activity_name = d.pop("activity_name")

        purpose = d.pop("purpose", UNSET)

        legal_basis = d.pop("legal_basis", UNSET)

        data_categories = cast(list[str], d.pop("data_categories", UNSET))

        data_subjects = cast(list[str], d.pop("data_subjects", UNSET))

        retention_period_days = d.pop("retention_period_days", UNSET)

        third_party_recipients = cast(list[str], d.pop("third_party_recipients", UNSET))

        international_transfers = cast(list[str], d.pop("international_transfers", UNSET))

        dpiad_required = d.pop("dpiad_required", UNSET)

        processing_activity_create = cls(
            activity_name=activity_name,
            purpose=purpose,
            legal_basis=legal_basis,
            data_categories=data_categories,
            data_subjects=data_subjects,
            retention_period_days=retention_period_days,
            third_party_recipients=third_party_recipients,
            international_transfers=international_transfers,
            dpiad_required=dpiad_required,
        )

        processing_activity_create.additional_properties = d
        return processing_activity_create

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
