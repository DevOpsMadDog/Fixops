from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.change_request_create_rules_json_item import ChangeRequestCreateRulesJsonItem


T = TypeVar("T", bound="ChangeRequestCreate")


@_attrs_define
class ChangeRequestCreate:
    """
    Attributes:
        firewall_id (str):
        change_type (str | Unset):  Default: 'add'.
        requester (str | Unset):  Default: ''.
        business_justification (str | Unset):  Default: ''.
        rules_json (list[ChangeRequestCreateRulesJsonItem] | Unset):
        expiry_date (None | str | Unset):
        risk_assessment (str | Unset):  Default: ''.
    """

    firewall_id: str
    change_type: str | Unset = "add"
    requester: str | Unset = ""
    business_justification: str | Unset = ""
    rules_json: list[ChangeRequestCreateRulesJsonItem] | Unset = UNSET
    expiry_date: None | str | Unset = UNSET
    risk_assessment: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        firewall_id = self.firewall_id

        change_type = self.change_type

        requester = self.requester

        business_justification = self.business_justification

        rules_json: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.rules_json, Unset):
            rules_json = []
            for rules_json_item_data in self.rules_json:
                rules_json_item = rules_json_item_data.to_dict()
                rules_json.append(rules_json_item)

        expiry_date: None | str | Unset
        if isinstance(self.expiry_date, Unset):
            expiry_date = UNSET
        else:
            expiry_date = self.expiry_date

        risk_assessment = self.risk_assessment

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "firewall_id": firewall_id,
            }
        )
        if change_type is not UNSET:
            field_dict["change_type"] = change_type
        if requester is not UNSET:
            field_dict["requester"] = requester
        if business_justification is not UNSET:
            field_dict["business_justification"] = business_justification
        if rules_json is not UNSET:
            field_dict["rules_json"] = rules_json
        if expiry_date is not UNSET:
            field_dict["expiry_date"] = expiry_date
        if risk_assessment is not UNSET:
            field_dict["risk_assessment"] = risk_assessment

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.change_request_create_rules_json_item import ChangeRequestCreateRulesJsonItem

        d = dict(src_dict)
        firewall_id = d.pop("firewall_id")

        change_type = d.pop("change_type", UNSET)

        requester = d.pop("requester", UNSET)

        business_justification = d.pop("business_justification", UNSET)

        _rules_json = d.pop("rules_json", UNSET)
        rules_json: list[ChangeRequestCreateRulesJsonItem] | Unset = UNSET
        if _rules_json is not UNSET:
            rules_json = []
            for rules_json_item_data in _rules_json:
                rules_json_item = ChangeRequestCreateRulesJsonItem.from_dict(rules_json_item_data)

                rules_json.append(rules_json_item)

        def _parse_expiry_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expiry_date = _parse_expiry_date(d.pop("expiry_date", UNSET))

        risk_assessment = d.pop("risk_assessment", UNSET)

        change_request_create = cls(
            firewall_id=firewall_id,
            change_type=change_type,
            requester=requester,
            business_justification=business_justification,
            rules_json=rules_json,
            expiry_date=expiry_date,
            risk_assessment=risk_assessment,
        )

        change_request_create.additional_properties = d
        return change_request_create

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
