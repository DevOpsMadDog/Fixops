from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.bulk_generate_request_findings_item import BulkGenerateRequestFindingsItem
    from ..models.bulk_generate_request_repo_context_type_0 import BulkGenerateRequestRepoContextType0


T = TypeVar("T", bound="BulkGenerateRequest")


@_attrs_define
class BulkGenerateRequest:
    """Request to generate fixes for multiple findings.

    Attributes:
        findings (list[BulkGenerateRequestFindingsItem]): List of finding dicts
        repo_context (BulkGenerateRequestRepoContextType0 | None | Unset):
    """

    findings: list[BulkGenerateRequestFindingsItem]
    repo_context: BulkGenerateRequestRepoContextType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.bulk_generate_request_repo_context_type_0 import BulkGenerateRequestRepoContextType0

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        repo_context: dict[str, Any] | None | Unset
        if isinstance(self.repo_context, Unset):
            repo_context = UNSET
        elif isinstance(self.repo_context, BulkGenerateRequestRepoContextType0):
            repo_context = self.repo_context.to_dict()
        else:
            repo_context = self.repo_context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if repo_context is not UNSET:
            field_dict["repo_context"] = repo_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_generate_request_findings_item import BulkGenerateRequestFindingsItem
        from ..models.bulk_generate_request_repo_context_type_0 import BulkGenerateRequestRepoContextType0

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = BulkGenerateRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        def _parse_repo_context(data: object) -> BulkGenerateRequestRepoContextType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                repo_context_type_0 = BulkGenerateRequestRepoContextType0.from_dict(data)

                return repo_context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BulkGenerateRequestRepoContextType0 | None | Unset, data)

        repo_context = _parse_repo_context(d.pop("repo_context", UNSET))

        bulk_generate_request = cls(
            findings=findings,
            repo_context=repo_context,
        )

        bulk_generate_request.additional_properties = d
        return bulk_generate_request

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
