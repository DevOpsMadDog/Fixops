from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.remediation_priority import RemediationPriority
from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePOAMRequest")


@_attrs_define
class CreatePOAMRequest:
    """
    Attributes:
        control_id (str): Control ID the POA&M addresses
        framework (str): Framework the control belongs to
        title (str): Short title for the POA&M item
        description (str): Detailed description of the finding and remediation plan
        responsible_party (str | Unset): Team or person responsible Default: 'Security Team'.
        risk_level (RemediationPriority | Unset):
        target_date (None | str | Unset): ISO8601 target remediation date
    """

    control_id: str
    framework: str
    title: str
    description: str
    responsible_party: str | Unset = "Security Team"
    risk_level: RemediationPriority | Unset = UNSET
    target_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        framework = self.framework

        title = self.title

        description = self.description

        responsible_party = self.responsible_party

        risk_level: str | Unset = UNSET
        if not isinstance(self.risk_level, Unset):
            risk_level = self.risk_level.value

        target_date: None | str | Unset
        if isinstance(self.target_date, Unset):
            target_date = UNSET
        else:
            target_date = self.target_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "framework": framework,
                "title": title,
                "description": description,
            }
        )
        if responsible_party is not UNSET:
            field_dict["responsible_party"] = responsible_party
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if target_date is not UNSET:
            field_dict["target_date"] = target_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        framework = d.pop("framework")

        title = d.pop("title")

        description = d.pop("description")

        responsible_party = d.pop("responsible_party", UNSET)

        _risk_level = d.pop("risk_level", UNSET)
        risk_level: RemediationPriority | Unset
        if isinstance(_risk_level, Unset):
            risk_level = UNSET
        else:
            risk_level = RemediationPriority(_risk_level)

        def _parse_target_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_date = _parse_target_date(d.pop("target_date", UNSET))

        create_poam_request = cls(
            control_id=control_id,
            framework=framework,
            title=title,
            description=description,
            responsible_party=responsible_party,
            risk_level=risk_level,
            target_date=target_date,
        )

        create_poam_request.additional_properties = d
        return create_poam_request

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
