from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdatePenTestRequestModel")


@_attrs_define
class UpdatePenTestRequestModel:
    """Model for updating pen test request.

    Attributes:
        status (None | str | Unset):
        mpte_job_id (None | str | Unset):
    """

    status: None | str | Unset = UNSET
    mpte_job_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        mpte_job_id: None | str | Unset
        if isinstance(self.mpte_job_id, Unset):
            mpte_job_id = UNSET
        else:
            mpte_job_id = self.mpte_job_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if status is not UNSET:
            field_dict["status"] = status
        if mpte_job_id is not UNSET:
            field_dict["mpte_job_id"] = mpte_job_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_mpte_job_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mpte_job_id = _parse_mpte_job_id(d.pop("mpte_job_id", UNSET))

        update_pen_test_request_model = cls(
            status=status,
            mpte_job_id=mpte_job_id,
        )

        update_pen_test_request_model.additional_properties = d
        return update_pen_test_request_model

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
