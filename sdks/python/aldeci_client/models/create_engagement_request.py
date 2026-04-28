from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateEngagementRequest")


@_attrs_define
class CreateEngagementRequest:
    """
    Attributes:
        name (str):
        engagement_type (str | Unset):  Default: 'external'.
        scope (str | Unset):  Default: ''.
        methodology (str | Unset):  Default: 'PTES'.
        status (str | Unset):  Default: 'planned'.
        start_date (str | Unset):  Default: ''.
        end_date (str | Unset):  Default: ''.
        lead_tester (str | Unset):  Default: ''.
        client_contact (str | Unset):  Default: ''.
        rules_of_engagement (str | Unset):  Default: ''.
    """

    name: str
    engagement_type: str | Unset = "external"
    scope: str | Unset = ""
    methodology: str | Unset = "PTES"
    status: str | Unset = "planned"
    start_date: str | Unset = ""
    end_date: str | Unset = ""
    lead_tester: str | Unset = ""
    client_contact: str | Unset = ""
    rules_of_engagement: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        engagement_type = self.engagement_type

        scope = self.scope

        methodology = self.methodology

        status = self.status

        start_date = self.start_date

        end_date = self.end_date

        lead_tester = self.lead_tester

        client_contact = self.client_contact

        rules_of_engagement = self.rules_of_engagement

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if engagement_type is not UNSET:
            field_dict["engagement_type"] = engagement_type
        if scope is not UNSET:
            field_dict["scope"] = scope
        if methodology is not UNSET:
            field_dict["methodology"] = methodology
        if status is not UNSET:
            field_dict["status"] = status
        if start_date is not UNSET:
            field_dict["start_date"] = start_date
        if end_date is not UNSET:
            field_dict["end_date"] = end_date
        if lead_tester is not UNSET:
            field_dict["lead_tester"] = lead_tester
        if client_contact is not UNSET:
            field_dict["client_contact"] = client_contact
        if rules_of_engagement is not UNSET:
            field_dict["rules_of_engagement"] = rules_of_engagement

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        engagement_type = d.pop("engagement_type", UNSET)

        scope = d.pop("scope", UNSET)

        methodology = d.pop("methodology", UNSET)

        status = d.pop("status", UNSET)

        start_date = d.pop("start_date", UNSET)

        end_date = d.pop("end_date", UNSET)

        lead_tester = d.pop("lead_tester", UNSET)

        client_contact = d.pop("client_contact", UNSET)

        rules_of_engagement = d.pop("rules_of_engagement", UNSET)

        create_engagement_request = cls(
            name=name,
            engagement_type=engagement_type,
            scope=scope,
            methodology=methodology,
            status=status,
            start_date=start_date,
            end_date=end_date,
            lead_tester=lead_tester,
            client_contact=client_contact,
            rules_of_engagement=rules_of_engagement,
        )

        create_engagement_request.additional_properties = d
        return create_engagement_request

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
