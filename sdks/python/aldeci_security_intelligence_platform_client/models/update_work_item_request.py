from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_work_item_request_additional_fields_type_0 import UpdateWorkItemRequestAdditionalFieldsType0


T = TypeVar("T", bound="UpdateWorkItemRequest")


@_attrs_define
class UpdateWorkItemRequest:
    """Request to update a work item in an ALM system.

    Attributes:
        status (None | str | Unset):
        assignee (None | str | Unset):
        labels (list[str] | None | Unset):
        comment (None | str | Unset):
        additional_fields (None | Unset | UpdateWorkItemRequestAdditionalFieldsType0):
    """

    status: None | str | Unset = UNSET
    assignee: None | str | Unset = UNSET
    labels: list[str] | None | Unset = UNSET
    comment: None | str | Unset = UNSET
    additional_fields: None | Unset | UpdateWorkItemRequestAdditionalFieldsType0 = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.update_work_item_request_additional_fields_type_0 import (
            UpdateWorkItemRequestAdditionalFieldsType0,
        )

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        else:
            status = self.status

        assignee: None | str | Unset
        if isinstance(self.assignee, Unset):
            assignee = UNSET
        else:
            assignee = self.assignee

        labels: list[str] | None | Unset
        if isinstance(self.labels, Unset):
            labels = UNSET
        elif isinstance(self.labels, list):
            labels = self.labels

        else:
            labels = self.labels

        comment: None | str | Unset
        if isinstance(self.comment, Unset):
            comment = UNSET
        else:
            comment = self.comment

        additional_fields: dict[str, Any] | None | Unset
        if isinstance(self.additional_fields, Unset):
            additional_fields = UNSET
        elif isinstance(self.additional_fields, UpdateWorkItemRequestAdditionalFieldsType0):
            additional_fields = self.additional_fields.to_dict()
        else:
            additional_fields = self.additional_fields

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if status is not UNSET:
            field_dict["status"] = status
        if assignee is not UNSET:
            field_dict["assignee"] = assignee
        if labels is not UNSET:
            field_dict["labels"] = labels
        if comment is not UNSET:
            field_dict["comment"] = comment
        if additional_fields is not UNSET:
            field_dict["additional_fields"] = additional_fields

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_work_item_request_additional_fields_type_0 import (
            UpdateWorkItemRequestAdditionalFieldsType0,
        )

        d = dict(src_dict)

        def _parse_status(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_assignee(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assignee = _parse_assignee(d.pop("assignee", UNSET))

        def _parse_labels(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                labels_type_0 = cast(list[str], data)

                return labels_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        labels = _parse_labels(d.pop("labels", UNSET))

        def _parse_comment(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        comment = _parse_comment(d.pop("comment", UNSET))

        def _parse_additional_fields(data: object) -> None | Unset | UpdateWorkItemRequestAdditionalFieldsType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                additional_fields_type_0 = UpdateWorkItemRequestAdditionalFieldsType0.from_dict(data)

                return additional_fields_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | UpdateWorkItemRequestAdditionalFieldsType0, data)

        additional_fields = _parse_additional_fields(d.pop("additional_fields", UNSET))

        update_work_item_request = cls(
            status=status,
            assignee=assignee,
            labels=labels,
            comment=comment,
            additional_fields=additional_fields,
        )

        update_work_item_request.additional_properties = d
        return update_work_item_request

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
