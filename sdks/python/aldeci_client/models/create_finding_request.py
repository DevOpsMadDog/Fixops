from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateFindingRequest")


@_attrs_define
class CreateFindingRequest:
    """
    Attributes:
        firewall_id (str): Associated firewall ID
        finding_type (str): Type label, e.g. overly_permissive
        org_id (str | Unset): Organisation ID Default: 'default'.
        rule_id (None | str | Unset): Associated rule ID
        severity (str | Unset): critical/high/medium/low/info Default: 'medium'.
        description (str | Unset): Human-readable description Default: ''.
    """

    firewall_id: str
    finding_type: str
    org_id: str | Unset = "default"
    rule_id: None | str | Unset = UNSET
    severity: str | Unset = "medium"
    description: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        firewall_id = self.firewall_id

        finding_type = self.finding_type

        org_id = self.org_id

        rule_id: None | str | Unset
        if isinstance(self.rule_id, Unset):
            rule_id = UNSET
        else:
            rule_id = self.rule_id

        severity = self.severity

        description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "firewall_id": firewall_id,
                "finding_type": finding_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        firewall_id = d.pop("firewall_id")

        finding_type = d.pop("finding_type")

        org_id = d.pop("org_id", UNSET)

        def _parse_rule_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        rule_id = _parse_rule_id(d.pop("rule_id", UNSET))

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        create_finding_request = cls(
            firewall_id=firewall_id,
            finding_type=finding_type,
            org_id=org_id,
            rule_id=rule_id,
            severity=severity,
            description=description,
        )

        create_finding_request.additional_properties = d
        return create_finding_request

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
