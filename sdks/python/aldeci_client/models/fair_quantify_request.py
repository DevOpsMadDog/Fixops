from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.fair_quantify_request_finding_type_0 import FAIRQuantifyRequestFindingType0


T = TypeVar("T", bound="FAIRQuantifyRequest")


@_attrs_define
class FAIRQuantifyRequest:
    """POST /api/v1/risk/quantify-fair body — accepts either an existing
    scenario_id (re-quantify) or finding-derived parameters (quantify_finding).

        Attributes:
            scenario_id (None | str | Unset): Existing scenario id to quantify
            finding (FAIRQuantifyRequestFindingType0 | None | Unset): Finding payload to derive parameters from (severity,
                asset_type, ...)
    """

    scenario_id: None | str | Unset = UNSET
    finding: FAIRQuantifyRequestFindingType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.fair_quantify_request_finding_type_0 import FAIRQuantifyRequestFindingType0

        scenario_id: None | str | Unset
        if isinstance(self.scenario_id, Unset):
            scenario_id = UNSET
        else:
            scenario_id = self.scenario_id

        finding: dict[str, Any] | None | Unset
        if isinstance(self.finding, Unset):
            finding = UNSET
        elif isinstance(self.finding, FAIRQuantifyRequestFindingType0):
            finding = self.finding.to_dict()
        else:
            finding = self.finding

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if scenario_id is not UNSET:
            field_dict["scenario_id"] = scenario_id
        if finding is not UNSET:
            field_dict["finding"] = finding

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fair_quantify_request_finding_type_0 import FAIRQuantifyRequestFindingType0

        d = dict(src_dict)

        def _parse_scenario_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scenario_id = _parse_scenario_id(d.pop("scenario_id", UNSET))

        def _parse_finding(data: object) -> FAIRQuantifyRequestFindingType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                finding_type_0 = FAIRQuantifyRequestFindingType0.from_dict(data)

                return finding_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FAIRQuantifyRequestFindingType0 | None | Unset, data)

        finding = _parse_finding(d.pop("finding", UNSET))

        fair_quantify_request = cls(
            scenario_id=scenario_id,
            finding=finding,
        )

        fair_quantify_request.additional_properties = d
        return fair_quantify_request

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
