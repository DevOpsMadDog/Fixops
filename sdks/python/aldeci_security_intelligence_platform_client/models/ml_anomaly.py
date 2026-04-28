from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.anomaly_category import AnomalyCategory
from ..models.feedback_label import FeedbackLabel
from ..models.risk_level import RiskLevel
from ..models.time_series_pattern import TimeSeriesPattern
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ml_anomaly_context import MLAnomalyContext


T = TypeVar("T", bound="MLAnomaly")


@_attrs_define
class MLAnomaly:
    """A detected ML/behavioral anomaly.

    Attributes:
        entity_id (str):
        entity_type (str):
        metric_name (str):
        category (AnomalyCategory):
        observed_value (float):
        expected_value (float):
        risk_level (RiskLevel):
        description (str):
        id (str | Unset):
        pattern (None | TimeSeriesPattern | Unset):
        z_score (float | None | Unset):
        isolation_score (float | None | Unset):
        detected_at (datetime.datetime | Unset):
        context (MLAnomalyContext | Unset):
        org_id (str | Unset):  Default: 'default'.
        feedback (FeedbackLabel | None | Unset):
        feedback_at (datetime.datetime | None | Unset):
    """

    entity_id: str
    entity_type: str
    metric_name: str
    category: AnomalyCategory
    observed_value: float
    expected_value: float
    risk_level: RiskLevel
    description: str
    id: str | Unset = UNSET
    pattern: None | TimeSeriesPattern | Unset = UNSET
    z_score: float | None | Unset = UNSET
    isolation_score: float | None | Unset = UNSET
    detected_at: datetime.datetime | Unset = UNSET
    context: MLAnomalyContext | Unset = UNSET
    org_id: str | Unset = "default"
    feedback: FeedbackLabel | None | Unset = UNSET
    feedback_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        entity_type = self.entity_type

        metric_name = self.metric_name

        category = self.category.value

        observed_value = self.observed_value

        expected_value = self.expected_value

        risk_level = self.risk_level.value

        description = self.description

        id = self.id

        pattern: None | str | Unset
        if isinstance(self.pattern, Unset):
            pattern = UNSET
        elif isinstance(self.pattern, TimeSeriesPattern):
            pattern = self.pattern.value
        else:
            pattern = self.pattern

        z_score: float | None | Unset
        if isinstance(self.z_score, Unset):
            z_score = UNSET
        else:
            z_score = self.z_score

        isolation_score: float | None | Unset
        if isinstance(self.isolation_score, Unset):
            isolation_score = UNSET
        else:
            isolation_score = self.isolation_score

        detected_at: str | Unset = UNSET
        if not isinstance(self.detected_at, Unset):
            detected_at = self.detected_at.isoformat()

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        org_id = self.org_id

        feedback: None | str | Unset
        if isinstance(self.feedback, Unset):
            feedback = UNSET
        elif isinstance(self.feedback, FeedbackLabel):
            feedback = self.feedback.value
        else:
            feedback = self.feedback

        feedback_at: None | str | Unset
        if isinstance(self.feedback_at, Unset):
            feedback_at = UNSET
        elif isinstance(self.feedback_at, datetime.datetime):
            feedback_at = self.feedback_at.isoformat()
        else:
            feedback_at = self.feedback_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "entity_type": entity_type,
                "metric_name": metric_name,
                "category": category,
                "observed_value": observed_value,
                "expected_value": expected_value,
                "risk_level": risk_level,
                "description": description,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if pattern is not UNSET:
            field_dict["pattern"] = pattern
        if z_score is not UNSET:
            field_dict["z_score"] = z_score
        if isolation_score is not UNSET:
            field_dict["isolation_score"] = isolation_score
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at
        if context is not UNSET:
            field_dict["context"] = context
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if feedback is not UNSET:
            field_dict["feedback"] = feedback
        if feedback_at is not UNSET:
            field_dict["feedback_at"] = feedback_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ml_anomaly_context import MLAnomalyContext

        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        entity_type = d.pop("entity_type")

        metric_name = d.pop("metric_name")

        category = AnomalyCategory(d.pop("category"))

        observed_value = d.pop("observed_value")

        expected_value = d.pop("expected_value")

        risk_level = RiskLevel(d.pop("risk_level"))

        description = d.pop("description")

        id = d.pop("id", UNSET)

        def _parse_pattern(data: object) -> None | TimeSeriesPattern | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                pattern_type_0 = TimeSeriesPattern(data)

                return pattern_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | TimeSeriesPattern | Unset, data)

        pattern = _parse_pattern(d.pop("pattern", UNSET))

        def _parse_z_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        z_score = _parse_z_score(d.pop("z_score", UNSET))

        def _parse_isolation_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        isolation_score = _parse_isolation_score(d.pop("isolation_score", UNSET))

        _detected_at = d.pop("detected_at", UNSET)
        detected_at: datetime.datetime | Unset
        if isinstance(_detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = isoparse(_detected_at)

        _context = d.pop("context", UNSET)
        context: MLAnomalyContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = MLAnomalyContext.from_dict(_context)

        org_id = d.pop("org_id", UNSET)

        def _parse_feedback(data: object) -> FeedbackLabel | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                feedback_type_0 = FeedbackLabel(data)

                return feedback_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FeedbackLabel | None | Unset, data)

        feedback = _parse_feedback(d.pop("feedback", UNSET))

        def _parse_feedback_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                feedback_at_type_0 = isoparse(data)

                return feedback_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        feedback_at = _parse_feedback_at(d.pop("feedback_at", UNSET))

        ml_anomaly = cls(
            entity_id=entity_id,
            entity_type=entity_type,
            metric_name=metric_name,
            category=category,
            observed_value=observed_value,
            expected_value=expected_value,
            risk_level=risk_level,
            description=description,
            id=id,
            pattern=pattern,
            z_score=z_score,
            isolation_score=isolation_score,
            detected_at=detected_at,
            context=context,
            org_id=org_id,
            feedback=feedback,
            feedback_at=feedback_at,
        )

        ml_anomaly.additional_properties = d
        return ml_anomaly

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
