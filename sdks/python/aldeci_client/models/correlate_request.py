from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.correlate_request_finding import CorrelateRequestFinding


T = TypeVar("T", bound="CorrelateRequest")


@_attrs_define
class CorrelateRequest:
    """Request body for finding correlation.

    Attributes:
        finding (CorrelateRequestFinding):
    """

    finding: CorrelateRequestFinding
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.correlate_request_finding import CorrelateRequestFinding

        d = dict(src_dict)
        finding = CorrelateRequestFinding.from_dict(d.pop("finding"))

        correlate_request = cls(
            finding=finding,
        )

        correlate_request.additional_properties = d
        return correlate_request

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
