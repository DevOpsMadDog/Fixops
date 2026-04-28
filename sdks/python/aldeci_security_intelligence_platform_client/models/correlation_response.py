from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.correlation_response_result import CorrelationResponseResult


T = TypeVar("T", bound="CorrelationResponse")


@_attrs_define
class CorrelationResponse:
    """Cross-domain correlation response.

    Attributes:
        query (str):
        query_type (str):
        available (bool):
        result (CorrelationResponseResult):
    """

    query: str
    query_type: str
    available: bool
    result: CorrelationResponseResult
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query = self.query

        query_type = self.query_type

        available = self.available

        result = self.result.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query": query,
                "query_type": query_type,
                "available": available,
                "result": result,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.correlation_response_result import CorrelationResponseResult

        d = dict(src_dict)
        query = d.pop("query")

        query_type = d.pop("query_type")

        available = d.pop("available")

        result = CorrelationResponseResult.from_dict(d.pop("result"))

        correlation_response = cls(
            query=query,
            query_type=query_type,
            available=available,
            result=result,
        )

        correlation_response.additional_properties = d
        return correlation_response

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
