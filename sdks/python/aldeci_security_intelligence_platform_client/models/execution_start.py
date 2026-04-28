from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.execution_start_context import ExecutionStartContext


T = TypeVar("T", bound="ExecutionStart")


@_attrs_define
class ExecutionStart:
    """
    Attributes:
        workflow_id (str):
        initiated_by (str | Unset):  Default: ''.
        context (ExecutionStartContext | Unset):
    """

    workflow_id: str
    initiated_by: str | Unset = ""
    context: ExecutionStartContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        workflow_id = self.workflow_id

        initiated_by = self.initiated_by

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "workflow_id": workflow_id,
            }
        )
        if initiated_by is not UNSET:
            field_dict["initiated_by"] = initiated_by
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.execution_start_context import ExecutionStartContext

        d = dict(src_dict)
        workflow_id = d.pop("workflow_id")

        initiated_by = d.pop("initiated_by", UNSET)

        _context = d.pop("context", UNSET)
        context: ExecutionStartContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = ExecutionStartContext.from_dict(_context)

        execution_start = cls(
            workflow_id=workflow_id,
            initiated_by=initiated_by,
            context=context,
        )

        execution_start.additional_properties = d
        return execution_start

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
