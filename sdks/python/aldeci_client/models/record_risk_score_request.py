from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordRiskScoreRequest")


@_attrs_define
class RecordRiskScoreRequest:
    """
    Attributes:
        entity_id (str): Unique identifier for the entity
        risk_score (float): Risk score 0-100
        entity_name (None | str | Unset): Human-readable entity name Default: ''.
        entity_type (str | Unset): asset | user | network | application | vendor Default: 'asset'.
        source_engine (None | str | Unset): Engine producing the score Default: ''.
        risk_factors (list[str] | None | Unset): Contributing risk factors
        severity (None | str | Unset): Override severity: critical | high | medium | low (auto-derived if omitted)
    """

    entity_id: str
    risk_score: float
    entity_name: None | str | Unset = ""
    entity_type: str | Unset = "asset"
    source_engine: None | str | Unset = ""
    risk_factors: list[str] | None | Unset = UNSET
    severity: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        risk_score = self.risk_score

        entity_name: None | str | Unset
        if isinstance(self.entity_name, Unset):
            entity_name = UNSET
        else:
            entity_name = self.entity_name

        entity_type = self.entity_type

        source_engine: None | str | Unset
        if isinstance(self.source_engine, Unset):
            source_engine = UNSET
        else:
            source_engine = self.source_engine

        risk_factors: list[str] | None | Unset
        if isinstance(self.risk_factors, Unset):
            risk_factors = UNSET
        elif isinstance(self.risk_factors, list):
            risk_factors = self.risk_factors

        else:
            risk_factors = self.risk_factors

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "risk_score": risk_score,
            }
        )
        if entity_name is not UNSET:
            field_dict["entity_name"] = entity_name
        if entity_type is not UNSET:
            field_dict["entity_type"] = entity_type
        if source_engine is not UNSET:
            field_dict["source_engine"] = source_engine
        if risk_factors is not UNSET:
            field_dict["risk_factors"] = risk_factors
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        risk_score = d.pop("risk_score")

        def _parse_entity_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        entity_name = _parse_entity_name(d.pop("entity_name", UNSET))

        entity_type = d.pop("entity_type", UNSET)

        def _parse_source_engine(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_engine = _parse_source_engine(d.pop("source_engine", UNSET))

        def _parse_risk_factors(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                risk_factors_type_0 = cast(list[str], data)

                return risk_factors_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        risk_factors = _parse_risk_factors(d.pop("risk_factors", UNSET))

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        record_risk_score_request = cls(
            entity_id=entity_id,
            risk_score=risk_score,
            entity_name=entity_name,
            entity_type=entity_type,
            source_engine=source_engine,
            risk_factors=risk_factors,
            severity=severity,
        )

        record_risk_score_request.additional_properties = d
        return record_risk_score_request

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
