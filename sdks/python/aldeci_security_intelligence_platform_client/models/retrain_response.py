from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RetrainResponse")


@_attrs_define
class RetrainResponse:
    """Response for ML model retraining.

    Attributes:
        job_id (str):
        status (str):
        models_queued (list[str]):
        estimated_time (str):
        data_points (int):
    """

    job_id: str
    status: str
    models_queued: list[str]
    estimated_time: str
    data_points: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        job_id = self.job_id

        status = self.status

        models_queued = self.models_queued

        estimated_time = self.estimated_time

        data_points = self.data_points

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "job_id": job_id,
                "status": status,
                "models_queued": models_queued,
                "estimated_time": estimated_time,
                "data_points": data_points,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        job_id = d.pop("job_id")

        status = d.pop("status")

        models_queued = cast(list[str], d.pop("models_queued"))

        estimated_time = d.pop("estimated_time")

        data_points = d.pop("data_points")

        retrain_response = cls(
            job_id=job_id,
            status=status,
            models_queued=models_queued,
            estimated_time=estimated_time,
            data_points=data_points,
        )

        retrain_response.additional_properties = d
        return retrain_response

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
