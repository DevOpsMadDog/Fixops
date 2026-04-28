from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.compare_request_finding_a import CompareRequestFindingA
    from ..models.compare_request_finding_b import CompareRequestFindingB


T = TypeVar("T", bound="CompareRequest")


@_attrs_define
class CompareRequest:
    """Two findings to compare side-by-side.

    Attributes:
        finding_a (CompareRequestFindingA): First finding
        finding_b (CompareRequestFindingB): Second finding
    """

    finding_a: CompareRequestFindingA
    finding_b: CompareRequestFindingB
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_a = self.finding_a.to_dict()

        finding_b = self.finding_b.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_a": finding_a,
                "finding_b": finding_b,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compare_request_finding_a import CompareRequestFindingA
        from ..models.compare_request_finding_b import CompareRequestFindingB

        d = dict(src_dict)
        finding_a = CompareRequestFindingA.from_dict(d.pop("finding_a"))

        finding_b = CompareRequestFindingB.from_dict(d.pop("finding_b"))

        compare_request = cls(
            finding_a=finding_a,
            finding_b=finding_b,
        )

        compare_request.additional_properties = d
        return compare_request

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
