from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddTestRequest")


@_attrs_define
class AddTestRequest:
    """
    Attributes:
        test_name (str):
        test_type (str | Unset):  Default: 'automated'.
        expected_result (str | Unset):  Default: ''.
        evidence (str | Unset):  Default: ''.
    """

    test_name: str
    test_type: str | Unset = "automated"
    expected_result: str | Unset = ""
    evidence: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        test_name = self.test_name

        test_type = self.test_type

        expected_result = self.expected_result

        evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "test_name": test_name,
            }
        )
        if test_type is not UNSET:
            field_dict["test_type"] = test_type
        if expected_result is not UNSET:
            field_dict["expected_result"] = expected_result
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        test_name = d.pop("test_name")

        test_type = d.pop("test_type", UNSET)

        expected_result = d.pop("expected_result", UNSET)

        evidence = d.pop("evidence", UNSET)

        add_test_request = cls(
            test_name=test_name,
            test_type=test_type,
            expected_result=expected_result,
            evidence=evidence,
        )

        add_test_request.additional_properties = d
        return add_test_request

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
