from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.operator_feedback_request_feedback_type import OperatorFeedbackRequestFeedbackType
from ..types import UNSET, Unset

T = TypeVar("T", bound="OperatorFeedbackRequest")


@_attrs_define
class OperatorFeedbackRequest:
    """Request to record operator feedback for correlation corrections.

    Attributes:
        cluster_id (str):
        feedback_type (OperatorFeedbackRequestFeedbackType): merge_allowed, merge_blocked, or split_cluster
        target_cluster_id (None | str | Unset):
        reason (None | str | Unset):
        operator_id (None | str | Unset):
    """

    cluster_id: str
    feedback_type: OperatorFeedbackRequestFeedbackType
    target_cluster_id: None | str | Unset = UNSET
    reason: None | str | Unset = UNSET
    operator_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cluster_id = self.cluster_id

        feedback_type = self.feedback_type.value

        target_cluster_id: None | str | Unset
        if isinstance(self.target_cluster_id, Unset):
            target_cluster_id = UNSET
        else:
            target_cluster_id = self.target_cluster_id

        reason: None | str | Unset
        if isinstance(self.reason, Unset):
            reason = UNSET
        else:
            reason = self.reason

        operator_id: None | str | Unset
        if isinstance(self.operator_id, Unset):
            operator_id = UNSET
        else:
            operator_id = self.operator_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cluster_id": cluster_id,
                "feedback_type": feedback_type,
            }
        )
        if target_cluster_id is not UNSET:
            field_dict["target_cluster_id"] = target_cluster_id
        if reason is not UNSET:
            field_dict["reason"] = reason
        if operator_id is not UNSET:
            field_dict["operator_id"] = operator_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cluster_id = d.pop("cluster_id")

        feedback_type = OperatorFeedbackRequestFeedbackType(d.pop("feedback_type"))

        def _parse_target_cluster_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_cluster_id = _parse_target_cluster_id(d.pop("target_cluster_id", UNSET))

        def _parse_reason(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reason = _parse_reason(d.pop("reason", UNSET))

        def _parse_operator_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        operator_id = _parse_operator_id(d.pop("operator_id", UNSET))

        operator_feedback_request = cls(
            cluster_id=cluster_id,
            feedback_type=feedback_type,
            target_cluster_id=target_cluster_id,
            reason=reason,
            operator_id=operator_id,
        )

        operator_feedback_request.additional_properties = d
        return operator_feedback_request

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
