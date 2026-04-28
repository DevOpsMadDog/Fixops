from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MonteCarloRequest")


@_attrs_define
class MonteCarloRequest:
    """Request for Monte Carlo risk quantification.

    Attributes:
        threat_event_frequency_min (float | Unset): Min annual threat events Default: 0.1.
        threat_event_frequency_mode (float | Unset): Most likely annual threat events Default: 1.0.
        threat_event_frequency_max (float | Unset): Max annual threat events Default: 5.0.
        vulnerability_probability_min (float | Unset): Min probability of successful exploit Default: 0.1.
        vulnerability_probability_mode (float | Unset): Most likely probability Default: 0.5.
        vulnerability_probability_max (float | Unset): Max probability Default: 0.9.
        loss_magnitude_min (float | Unset): Minimum loss in dollars Default: 10000.0.
        loss_magnitude_mode (float | Unset): Most likely loss Default: 100000.0.
        loss_magnitude_max (float | Unset): Maximum loss Default: 1000000.0.
        iterations (int | Unset): Number of simulations Default: 10000.
        confidence_level (float | Unset): Confidence level for intervals Default: 0.95.
    """

    threat_event_frequency_min: float | Unset = 0.1
    threat_event_frequency_mode: float | Unset = 1.0
    threat_event_frequency_max: float | Unset = 5.0
    vulnerability_probability_min: float | Unset = 0.1
    vulnerability_probability_mode: float | Unset = 0.5
    vulnerability_probability_max: float | Unset = 0.9
    loss_magnitude_min: float | Unset = 10000.0
    loss_magnitude_mode: float | Unset = 100000.0
    loss_magnitude_max: float | Unset = 1000000.0
    iterations: int | Unset = 10000
    confidence_level: float | Unset = 0.95
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        threat_event_frequency_min = self.threat_event_frequency_min

        threat_event_frequency_mode = self.threat_event_frequency_mode

        threat_event_frequency_max = self.threat_event_frequency_max

        vulnerability_probability_min = self.vulnerability_probability_min

        vulnerability_probability_mode = self.vulnerability_probability_mode

        vulnerability_probability_max = self.vulnerability_probability_max

        loss_magnitude_min = self.loss_magnitude_min

        loss_magnitude_mode = self.loss_magnitude_mode

        loss_magnitude_max = self.loss_magnitude_max

        iterations = self.iterations

        confidence_level = self.confidence_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if threat_event_frequency_min is not UNSET:
            field_dict["threat_event_frequency_min"] = threat_event_frequency_min
        if threat_event_frequency_mode is not UNSET:
            field_dict["threat_event_frequency_mode"] = threat_event_frequency_mode
        if threat_event_frequency_max is not UNSET:
            field_dict["threat_event_frequency_max"] = threat_event_frequency_max
        if vulnerability_probability_min is not UNSET:
            field_dict["vulnerability_probability_min"] = vulnerability_probability_min
        if vulnerability_probability_mode is not UNSET:
            field_dict["vulnerability_probability_mode"] = vulnerability_probability_mode
        if vulnerability_probability_max is not UNSET:
            field_dict["vulnerability_probability_max"] = vulnerability_probability_max
        if loss_magnitude_min is not UNSET:
            field_dict["loss_magnitude_min"] = loss_magnitude_min
        if loss_magnitude_mode is not UNSET:
            field_dict["loss_magnitude_mode"] = loss_magnitude_mode
        if loss_magnitude_max is not UNSET:
            field_dict["loss_magnitude_max"] = loss_magnitude_max
        if iterations is not UNSET:
            field_dict["iterations"] = iterations
        if confidence_level is not UNSET:
            field_dict["confidence_level"] = confidence_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        threat_event_frequency_min = d.pop("threat_event_frequency_min", UNSET)

        threat_event_frequency_mode = d.pop("threat_event_frequency_mode", UNSET)

        threat_event_frequency_max = d.pop("threat_event_frequency_max", UNSET)

        vulnerability_probability_min = d.pop("vulnerability_probability_min", UNSET)

        vulnerability_probability_mode = d.pop("vulnerability_probability_mode", UNSET)

        vulnerability_probability_max = d.pop("vulnerability_probability_max", UNSET)

        loss_magnitude_min = d.pop("loss_magnitude_min", UNSET)

        loss_magnitude_mode = d.pop("loss_magnitude_mode", UNSET)

        loss_magnitude_max = d.pop("loss_magnitude_max", UNSET)

        iterations = d.pop("iterations", UNSET)

        confidence_level = d.pop("confidence_level", UNSET)

        monte_carlo_request = cls(
            threat_event_frequency_min=threat_event_frequency_min,
            threat_event_frequency_mode=threat_event_frequency_mode,
            threat_event_frequency_max=threat_event_frequency_max,
            vulnerability_probability_min=vulnerability_probability_min,
            vulnerability_probability_mode=vulnerability_probability_mode,
            vulnerability_probability_max=vulnerability_probability_max,
            loss_magnitude_min=loss_magnitude_min,
            loss_magnitude_mode=loss_magnitude_mode,
            loss_magnitude_max=loss_magnitude_max,
            iterations=iterations,
            confidence_level=confidence_level,
        )

        monte_carlo_request.additional_properties = d
        return monte_carlo_request

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
