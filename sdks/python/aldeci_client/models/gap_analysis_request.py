from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.compliance_framework import ComplianceFramework
from ..types import UNSET, Unset

T = TypeVar("T", bound="GapAnalysisRequest")


@_attrs_define
class GapAnalysisRequest:
    """Request for compliance gap analysis.

    Attributes:
        framework (ComplianceFramework): Compliance frameworks.
        scope (list[str] | None | Unset):
    """

    framework: ComplianceFramework
    scope: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        framework = self.framework.value

        scope: list[str] | None | Unset
        if isinstance(self.scope, Unset):
            scope = UNSET
        elif isinstance(self.scope, list):
            scope = self.scope

        else:
            scope = self.scope

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "framework": framework,
            }
        )
        if scope is not UNSET:
            field_dict["scope"] = scope

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        framework = ComplianceFramework(d.pop("framework"))

        def _parse_scope(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                scope_type_0 = cast(list[str], data)

                return scope_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        scope = _parse_scope(d.pop("scope", UNSET))

        gap_analysis_request = cls(
            framework=framework,
            scope=scope,
        )

        gap_analysis_request.additional_properties = d
        return gap_analysis_request

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
