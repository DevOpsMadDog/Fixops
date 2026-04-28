from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePenTestRequestModel")


@_attrs_define
class CreatePenTestRequestModel:
    """Model for creating pen test request.

    Security: All string fields have length limits. target_url validated
    for SSRF at the endpoint level (not in Pydantic, to give clear HTTP error).

        Attributes:
            finding_id (str):
            target_url (str):
            vulnerability_type (str):
            test_case (str):
            priority (str | Unset):  Default: 'medium'.
            auto_verify (bool | Unset):  Default: True.
    """

    finding_id: str
    target_url: str
    vulnerability_type: str
    test_case: str
    priority: str | Unset = "medium"
    auto_verify: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        target_url = self.target_url

        vulnerability_type = self.vulnerability_type

        test_case = self.test_case

        priority = self.priority

        auto_verify = self.auto_verify

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "target_url": target_url,
                "vulnerability_type": vulnerability_type,
                "test_case": test_case,
            }
        )
        if priority is not UNSET:
            field_dict["priority"] = priority
        if auto_verify is not UNSET:
            field_dict["auto_verify"] = auto_verify

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        target_url = d.pop("target_url")

        vulnerability_type = d.pop("vulnerability_type")

        test_case = d.pop("test_case")

        priority = d.pop("priority", UNSET)

        auto_verify = d.pop("auto_verify", UNSET)

        create_pen_test_request_model = cls(
            finding_id=finding_id,
            target_url=target_url,
            vulnerability_type=vulnerability_type,
            test_case=test_case,
            priority=priority,
            auto_verify=auto_verify,
        )

        create_pen_test_request_model.additional_properties = d
        return create_pen_test_request_model

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
