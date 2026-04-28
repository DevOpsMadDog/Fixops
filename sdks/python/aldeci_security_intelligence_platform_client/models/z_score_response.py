from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ml_anomaly import MLAnomaly


T = TypeVar("T", bound="ZScoreResponse")


@_attrs_define
class ZScoreResponse:
    """
    Attributes:
        anomaly_detected (bool):
        message (str):
        anomaly (MLAnomaly | None | Unset):
    """

    anomaly_detected: bool
    message: str
    anomaly: MLAnomaly | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.ml_anomaly import MLAnomaly

        anomaly_detected = self.anomaly_detected

        message = self.message

        anomaly: dict[str, Any] | None | Unset
        if isinstance(self.anomaly, Unset):
            anomaly = UNSET
        elif isinstance(self.anomaly, MLAnomaly):
            anomaly = self.anomaly.to_dict()
        else:
            anomaly = self.anomaly

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "anomaly_detected": anomaly_detected,
                "message": message,
            }
        )
        if anomaly is not UNSET:
            field_dict["anomaly"] = anomaly

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ml_anomaly import MLAnomaly

        d = dict(src_dict)
        anomaly_detected = d.pop("anomaly_detected")

        message = d.pop("message")

        def _parse_anomaly(data: object) -> MLAnomaly | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                anomaly_type_0 = MLAnomaly.from_dict(data)

                return anomaly_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MLAnomaly | None | Unset, data)

        anomaly = _parse_anomaly(d.pop("anomaly", UNSET))

        z_score_response = cls(
            anomaly_detected=anomaly_detected,
            message=message,
            anomaly=anomaly,
        )

        z_score_response.additional_properties = d
        return z_score_response

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
