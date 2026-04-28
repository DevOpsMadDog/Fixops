from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.bulk_operation_response_errors_item import BulkOperationResponseErrorsItem


T = TypeVar("T", bound="BulkOperationResponse")


@_attrs_define
class BulkOperationResponse:
    """Response model for bulk operations.

    Attributes:
        success_count (int):
        failure_count (int):
        errors (list[BulkOperationResponseErrorsItem] | Unset):
    """

    success_count: int
    failure_count: int
    errors: list[BulkOperationResponseErrorsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        success_count = self.success_count

        failure_count = self.failure_count

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "success_count": success_count,
                "failure_count": failure_count,
            }
        )
        if errors is not UNSET:
            field_dict["errors"] = errors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_operation_response_errors_item import BulkOperationResponseErrorsItem

        d = dict(src_dict)
        success_count = d.pop("success_count")

        failure_count = d.pop("failure_count")

        _errors = d.pop("errors", UNSET)
        errors: list[BulkOperationResponseErrorsItem] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = BulkOperationResponseErrorsItem.from_dict(errors_item_data)

                errors.append(errors_item)

        bulk_operation_response = cls(
            success_count=success_count,
            failure_count=failure_count,
            errors=errors,
        )

        bulk_operation_response.additional_properties = d
        return bulk_operation_response

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
