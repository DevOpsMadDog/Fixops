from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExceptionRequest")


@_attrs_define
class ExceptionRequest:
    """
    Attributes:
        title (str):
        description (str | Unset):  Default: ''.
        exception_type (str | Unset):  Default: 'vulnerability'.
        risk_level (str | Unset):  Default: 'medium'.
        requestor (str | Unset):  Default: ''.
        approver (str | Unset):  Default: ''.
        business_justification (str | Unset):  Default: ''.
        compensating_controls (str | Unset):  Default: ''.
        expires_at (None | str | Unset):
    """

    title: str
    description: str | Unset = ""
    exception_type: str | Unset = "vulnerability"
    risk_level: str | Unset = "medium"
    requestor: str | Unset = ""
    approver: str | Unset = ""
    business_justification: str | Unset = ""
    compensating_controls: str | Unset = ""
    expires_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        description = self.description

        exception_type = self.exception_type

        risk_level = self.risk_level

        requestor = self.requestor

        approver = self.approver

        business_justification = self.business_justification

        compensating_controls = self.compensating_controls

        expires_at: None | str | Unset
        if isinstance(self.expires_at, Unset):
            expires_at = UNSET
        else:
            expires_at = self.expires_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if exception_type is not UNSET:
            field_dict["exception_type"] = exception_type
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if requestor is not UNSET:
            field_dict["requestor"] = requestor
        if approver is not UNSET:
            field_dict["approver"] = approver
        if business_justification is not UNSET:
            field_dict["business_justification"] = business_justification
        if compensating_controls is not UNSET:
            field_dict["compensating_controls"] = compensating_controls
        if expires_at is not UNSET:
            field_dict["expires_at"] = expires_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description", UNSET)

        exception_type = d.pop("exception_type", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        requestor = d.pop("requestor", UNSET)

        approver = d.pop("approver", UNSET)

        business_justification = d.pop("business_justification", UNSET)

        compensating_controls = d.pop("compensating_controls", UNSET)

        def _parse_expires_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        expires_at = _parse_expires_at(d.pop("expires_at", UNSET))

        exception_request = cls(
            title=title,
            description=description,
            exception_type=exception_type,
            risk_level=risk_level,
            requestor=requestor,
            approver=approver,
            business_justification=business_justification,
            compensating_controls=compensating_controls,
            expires_at=expires_at,
        )

        exception_request.additional_properties = d
        return exception_request

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
