from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.stage_matrix_request_stage_matrix import StageMatrixRequestStageMatrix


T = TypeVar("T", bound="StageMatrixRequest")


@_attrs_define
class StageMatrixRequest:
    """
    Attributes:
        policy_id (str):
        stage_matrix (StageMatrixRequestStageMatrix):
        org_id (str | Unset):  Default: 'default'.
    """

    policy_id: str
    stage_matrix: StageMatrixRequestStageMatrix
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        stage_matrix = self.stage_matrix.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "stage_matrix": stage_matrix,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.stage_matrix_request_stage_matrix import StageMatrixRequestStageMatrix

        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        stage_matrix = StageMatrixRequestStageMatrix.from_dict(d.pop("stage_matrix"))

        org_id = d.pop("org_id", UNSET)

        stage_matrix_request = cls(
            policy_id=policy_id,
            stage_matrix=stage_matrix,
            org_id=org_id,
        )

        stage_matrix_request.additional_properties = d
        return stage_matrix_request

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
