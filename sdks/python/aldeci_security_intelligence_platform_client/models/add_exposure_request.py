from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddExposureRequest")


@_attrs_define
class AddExposureRequest:
    """
    Attributes:
        title (str):
        description (str | Unset):  Default: ''.
        assets (list[str] | Unset):
        findings (list[str] | Unset):
        risk_score (float | Unset):  Default: 0.0.
        business_impact (str | Unset):  Default: ''.
        org_id (str | Unset):  Default: 'default'.
    """

    title: str
    description: str | Unset = ""
    assets: list[str] | Unset = UNSET
    findings: list[str] | Unset = UNSET
    risk_score: float | Unset = 0.0
    business_impact: str | Unset = ""
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        assets: list[str] | Unset = UNSET
        if not isinstance(self.assets, Unset):
            assets = self.assets

        findings: list[str] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = self.findings

        risk_score = self.risk_score

        business_impact = self.business_impact

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if assets is not UNSET:
            field_dict["assets"] = assets
        if findings is not UNSET:
            field_dict["findings"] = findings
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if business_impact is not UNSET:
            field_dict["business_impact"] = business_impact
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        assets = cast(list[str], d.pop("assets", UNSET))

        findings = cast(list[str], d.pop("findings", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        business_impact = d.pop("business_impact", UNSET)

        org_id = d.pop("org_id", UNSET)

        add_exposure_request = cls(
            title=title,
            description=description,
            assets=assets,
            findings=findings,
            risk_score=risk_score,
            business_impact=business_impact,
            org_id=org_id,
        )

        add_exposure_request.additional_properties = d
        return add_exposure_request

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
