from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AppRegisterRequest")


@_attrs_define
class AppRegisterRequest:
    """
    Attributes:
        name (str):
        app_type (str | Unset):  Default: 'web'.
        repo_url (str | Unset):  Default: ''.
        tech_stack (list[str] | Unset):
        risk_rating (str | Unset):  Default: 'medium'.
        last_scan (None | str | Unset):
        compliance_score (float | Unset):  Default: 0.0.
    """

    name: str
    app_type: str | Unset = "web"
    repo_url: str | Unset = ""
    tech_stack: list[str] | Unset = UNSET
    risk_rating: str | Unset = "medium"
    last_scan: None | str | Unset = UNSET
    compliance_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        app_type = self.app_type

        repo_url = self.repo_url

        tech_stack: list[str] | Unset = UNSET
        if not isinstance(self.tech_stack, Unset):
            tech_stack = self.tech_stack

        risk_rating = self.risk_rating

        last_scan: None | str | Unset
        if isinstance(self.last_scan, Unset):
            last_scan = UNSET
        else:
            last_scan = self.last_scan

        compliance_score = self.compliance_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if app_type is not UNSET:
            field_dict["app_type"] = app_type
        if repo_url is not UNSET:
            field_dict["repo_url"] = repo_url
        if tech_stack is not UNSET:
            field_dict["tech_stack"] = tech_stack
        if risk_rating is not UNSET:
            field_dict["risk_rating"] = risk_rating
        if last_scan is not UNSET:
            field_dict["last_scan"] = last_scan
        if compliance_score is not UNSET:
            field_dict["compliance_score"] = compliance_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        app_type = d.pop("app_type", UNSET)

        repo_url = d.pop("repo_url", UNSET)

        tech_stack = cast(list[str], d.pop("tech_stack", UNSET))

        risk_rating = d.pop("risk_rating", UNSET)

        def _parse_last_scan(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_scan = _parse_last_scan(d.pop("last_scan", UNSET))

        compliance_score = d.pop("compliance_score", UNSET)

        app_register_request = cls(
            name=name,
            app_type=app_type,
            repo_url=repo_url,
            tech_stack=tech_stack,
            risk_rating=risk_rating,
            last_scan=last_scan,
            compliance_score=compliance_score,
        )

        app_register_request.additional_properties = d
        return app_register_request

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
