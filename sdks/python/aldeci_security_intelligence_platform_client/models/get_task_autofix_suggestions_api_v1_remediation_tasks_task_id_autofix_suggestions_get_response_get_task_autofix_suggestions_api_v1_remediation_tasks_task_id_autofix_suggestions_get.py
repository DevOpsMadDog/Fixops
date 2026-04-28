from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar(
    "T",
    bound="GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet",
)


@_attrs_define
class GetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGetResponseGetTaskAutofixSuggestionsApiV1RemediationTasksTaskIdAutofixSuggestionsGet:
    """ """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get_response_get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get = cls()

        get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get_response_get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get.additional_properties = d
        return get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get_response_get_task_autofix_suggestions_api_v1_remediation_tasks_task_id_autofix_suggestions_get

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
