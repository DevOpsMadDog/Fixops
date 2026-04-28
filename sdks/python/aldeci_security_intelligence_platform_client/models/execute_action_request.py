from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.execute_action_request_parameters import ExecuteActionRequestParameters


T = TypeVar("T", bound="ExecuteActionRequest")


@_attrs_define
class ExecuteActionRequest:
    """Request to execute an agent action.

    Attributes:
        action_type (str): Type of action to execute
        parameters (ExecuteActionRequestParameters | Unset):
        async_execution (bool | Unset): Execute asynchronously Default: True.
    """

    action_type: str
    parameters: ExecuteActionRequestParameters | Unset = UNSET
    async_execution: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action_type = self.action_type

        parameters: dict[str, Any] | Unset = UNSET
        if not isinstance(self.parameters, Unset):
            parameters = self.parameters.to_dict()

        async_execution = self.async_execution

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action_type": action_type,
            }
        )
        if parameters is not UNSET:
            field_dict["parameters"] = parameters
        if async_execution is not UNSET:
            field_dict["async_execution"] = async_execution

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.execute_action_request_parameters import ExecuteActionRequestParameters

        d = dict(src_dict)
        action_type = d.pop("action_type")

        _parameters = d.pop("parameters", UNSET)
        parameters: ExecuteActionRequestParameters | Unset
        if isinstance(_parameters, Unset):
            parameters = UNSET
        else:
            parameters = ExecuteActionRequestParameters.from_dict(_parameters)

        async_execution = d.pop("async_execution", UNSET)

        execute_action_request = cls(
            action_type=action_type,
            parameters=parameters,
            async_execution=async_execution,
        )

        execute_action_request.additional_properties = d
        return execute_action_request

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
