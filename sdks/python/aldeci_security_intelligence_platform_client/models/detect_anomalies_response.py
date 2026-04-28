from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.anomaly_out import AnomalyOut


T = TypeVar("T", bound="DetectAnomaliesResponse")


@_attrs_define
class DetectAnomaliesResponse:
    """
    Attributes:
        anomalies (list[AnomalyOut]):
        count (int):
    """

    anomalies: list[AnomalyOut]
    count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        anomalies = []
        for anomalies_item_data in self.anomalies:
            anomalies_item = anomalies_item_data.to_dict()
            anomalies.append(anomalies_item)

        count = self.count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "anomalies": anomalies,
                "count": count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.anomaly_out import AnomalyOut

        d = dict(src_dict)
        anomalies = []
        _anomalies = d.pop("anomalies")
        for anomalies_item_data in _anomalies:
            anomalies_item = AnomalyOut.from_dict(anomalies_item_data)

            anomalies.append(anomalies_item)

        count = d.pop("count")

        detect_anomalies_response = cls(
            anomalies=anomalies,
            count=count,
        )

        detect_anomalies_response.additional_properties = d
        return detect_anomalies_response

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
