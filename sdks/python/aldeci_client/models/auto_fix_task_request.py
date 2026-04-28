from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auto_fix_task_request_repo_context_type_0 import AutoFixTaskRequestRepoContextType0


T = TypeVar("T", bound="AutoFixTaskRequest")


@_attrs_define
class AutoFixTaskRequest:
    """Request to generate autofix for a remediation task.

    Attributes:
        source_code (None | str | Unset):
        repo_context (AutoFixTaskRequestRepoContextType0 | None | Unset):
        repository (None | str | Unset):
        create_pr (bool | Unset):  Default: True.
    """

    source_code: None | str | Unset = UNSET
    repo_context: AutoFixTaskRequestRepoContextType0 | None | Unset = UNSET
    repository: None | str | Unset = UNSET
    create_pr: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.auto_fix_task_request_repo_context_type_0 import AutoFixTaskRequestRepoContextType0

        source_code: None | str | Unset
        if isinstance(self.source_code, Unset):
            source_code = UNSET
        else:
            source_code = self.source_code

        repo_context: dict[str, Any] | None | Unset
        if isinstance(self.repo_context, Unset):
            repo_context = UNSET
        elif isinstance(self.repo_context, AutoFixTaskRequestRepoContextType0):
            repo_context = self.repo_context.to_dict()
        else:
            repo_context = self.repo_context

        repository: None | str | Unset
        if isinstance(self.repository, Unset):
            repository = UNSET
        else:
            repository = self.repository

        create_pr = self.create_pr

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if source_code is not UNSET:
            field_dict["source_code"] = source_code
        if repo_context is not UNSET:
            field_dict["repo_context"] = repo_context
        if repository is not UNSET:
            field_dict["repository"] = repository
        if create_pr is not UNSET:
            field_dict["create_pr"] = create_pr

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_fix_task_request_repo_context_type_0 import AutoFixTaskRequestRepoContextType0

        d = dict(src_dict)

        def _parse_source_code(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_code = _parse_source_code(d.pop("source_code", UNSET))

        def _parse_repo_context(data: object) -> AutoFixTaskRequestRepoContextType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                repo_context_type_0 = AutoFixTaskRequestRepoContextType0.from_dict(data)

                return repo_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AutoFixTaskRequestRepoContextType0 | None | Unset, data)

        repo_context = _parse_repo_context(d.pop("repo_context", UNSET))

        def _parse_repository(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        repository = _parse_repository(d.pop("repository", UNSET))

        create_pr = d.pop("create_pr", UNSET)

        auto_fix_task_request = cls(
            source_code=source_code,
            repo_context=repo_context,
            repository=repository,
            create_pr=create_pr,
        )

        auto_fix_task_request.additional_properties = d
        return auto_fix_task_request

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
