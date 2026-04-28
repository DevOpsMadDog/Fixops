from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.explain_request_finding import ExplainRequestFinding


T = TypeVar("T", bound="ExplainRequest")


@_attrs_define
class ExplainRequest:
    """Finding to explain — full finding dict.

    Attributes:
        finding (ExplainRequestFinding): Raw finding dict
    """

    finding: ExplainRequestFinding
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
        from ..models.explain_request_finding import ExplainRequestFinding

        d = dict(src_dict)
        finding = ExplainRequestFinding.from_dict(d.pop("finding"))

        explain_request = cls(
            finding=finding,
        )

        explain_request.additional_properties = d
        return explain_request

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
