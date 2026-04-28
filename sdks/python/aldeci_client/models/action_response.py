from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.action_status import ActionStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.action_response_parameters import ActionResponseParameters
    from ..models.action_response_result_type_0 import ActionResponseResultType0


T = TypeVar("T", bound="ActionResponse")


@_attrs_define
class ActionResponse:
    """Agent action response.

    Attributes:
        id (str):
        session_id (str):
        action_type (str):
        status (ActionStatus): Status of an agent action.
        parameters (ActionResponseParameters):
        created_at (datetime.datetime):
        result (ActionResponseResultType0 | None | Unset):
        error (None | str | Unset):
        completed_at (datetime.datetime | None | Unset):
    """

    id: str
    session_id: str
    action_type: str
    status: ActionStatus
    parameters: ActionResponseParameters
    created_at: datetime.datetime
    result: ActionResponseResultType0 | None | Unset = UNSET
    error: None | str | Unset = UNSET
    completed_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.action_response_result_type_0 import ActionResponseResultType0

        id = self.id

        session_id = self.session_id

        action_type = self.action_type

        status = self.status.value

        parameters = self.parameters.to_dict()

        created_at = self.created_at.isoformat()

        result: dict[str, Any] | None | Unset
        if isinstance(self.result, Unset):
            result = UNSET
        elif isinstance(self.result, ActionResponseResultType0):
            result = self.result.to_dict()
        else:
            result = self.result

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        elif isinstance(self.completed_at, datetime.datetime):
            completed_at = self.completed_at.isoformat()
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "session_id": session_id,
                "action_type": action_type,
                "status": status,
                "parameters": parameters,
                "created_at": created_at,
            }
        )
        if result is not UNSET:
            field_dict["result"] = result
        if error is not UNSET:
            field_dict["error"] = error
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.action_response_parameters import ActionResponseParameters
        from ..models.action_response_result_type_0 import ActionResponseResultType0

        d = dict(src_dict)
        id = d.pop("id")

        session_id = d.pop("session_id")

        action_type = d.pop("action_type")

        status = ActionStatus(d.pop("status"))

        parameters = ActionResponseParameters.from_dict(d.pop("parameters"))

        created_at = isoparse(d.pop("created_at"))

        def _parse_result(data: object) -> ActionResponseResultType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                result_type_0 = ActionResponseResultType0.from_dict(data)

                return result_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ActionResponseResultType0 | None | Unset, data)

        result = _parse_result(d.pop("result", UNSET))

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        def _parse_completed_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                completed_at_type_0 = isoparse(data)

                return completed_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        action_response = cls(
            id=id,
            session_id=session_id,
            action_type=action_type,
            status=status,
            parameters=parameters,
            created_at=created_at,
            result=result,
            error=error,
            completed_at=completed_at,
        )

        action_response.additional_properties = d
        return action_response

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
