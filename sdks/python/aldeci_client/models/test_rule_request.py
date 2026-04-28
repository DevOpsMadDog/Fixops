from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.test_request_item import TestRequestItem


T = TypeVar("T", bound="TestRuleRequest")


@_attrs_define
class TestRuleRequest:
    """
    Attributes:
        requests (list[TestRequestItem]):
    """

    requests: list[TestRequestItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        requests = []
        for requests_item_data in self.requests:
            requests_item = requests_item_data.to_dict()
            requests.append(requests_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "requests": requests,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.test_request_item import TestRequestItem

        d = dict(src_dict)
        requests = []
        _requests = d.pop("requests")
        for requests_item_data in _requests:
            requests_item = TestRequestItem.from_dict(requests_item_data)

            requests.append(requests_item)

        test_rule_request = cls(
            requests=requests,
        )

        test_rule_request.additional_properties = d
        return test_rule_request

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
