from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.anomaly import Anomaly


T = TypeVar("T", bound="DetectResponse")


@_attrs_define
class DetectResponse:
    """
    Attributes:
        anomalies_found (int):
        anomalies (list[Anomaly]):
    """

    anomalies_found: int
    anomalies: list[Anomaly]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        anomalies_found = self.anomalies_found

        anomalies = []
        for anomalies_item_data in self.anomalies:
            anomalies_item = anomalies_item_data.to_dict()
            anomalies.append(anomalies_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "anomalies_found": anomalies_found,
                "anomalies": anomalies,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.anomaly import Anomaly

        d = dict(src_dict)
        anomalies_found = d.pop("anomalies_found")

        anomalies = []
        _anomalies = d.pop("anomalies")
        for anomalies_item_data in _anomalies:
            anomalies_item = Anomaly.from_dict(anomalies_item_data)

            anomalies.append(anomalies_item)

        detect_response = cls(
            anomalies_found=anomalies_found,
            anomalies=anomalies,
        )

        detect_response.additional_properties = d
        return detect_response

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
