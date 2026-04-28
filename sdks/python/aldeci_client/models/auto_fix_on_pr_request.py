from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auto_fix_on_pr_request_findings_item import AutoFixOnPRRequestFindingsItem
    from ..models.auto_fix_on_pr_request_repo_context import AutoFixOnPRRequestRepoContext


T = TypeVar("T", bound="AutoFixOnPRRequest")


@_attrs_define
class AutoFixOnPRRequest:
    """
    Attributes:
        org_id (str):
        installation_id (str):
        repo (str): owner/repo
        pr_number (int):
        head_sha (None | str | Unset):
        findings (list[AutoFixOnPRRequestFindingsItem] | Unset): Vulnerability findings (engine accepts
            Snyk/Trivy/Grype/Dependabot shapes).
        dry_run (bool | Unset): If true, do not POST to GitHub. Default: False.
        max_fixes (int | Unset):  Default: 25.
        repo_context (AutoFixOnPRRequestRepoContext | Unset):
    """

    org_id: str
    installation_id: str
    repo: str
    pr_number: int
    head_sha: None | str | Unset = UNSET
    findings: list[AutoFixOnPRRequestFindingsItem] | Unset = UNSET
    dry_run: bool | Unset = False
    max_fixes: int | Unset = 25
    repo_context: AutoFixOnPRRequestRepoContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        installation_id = self.installation_id

        repo = self.repo

        pr_number = self.pr_number

        head_sha: None | str | Unset
        if isinstance(self.head_sha, Unset):
            head_sha = UNSET
        else:
            head_sha = self.head_sha

        findings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = []
            for findings_item_data in self.findings:
                findings_item = findings_item_data.to_dict()
                findings.append(findings_item)

        dry_run = self.dry_run

        max_fixes = self.max_fixes

        repo_context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.repo_context, Unset):
            repo_context = self.repo_context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "installation_id": installation_id,
                "repo": repo,
                "pr_number": pr_number,
            }
        )
        if head_sha is not UNSET:
            field_dict["head_sha"] = head_sha
        if findings is not UNSET:
            field_dict["findings"] = findings
        if dry_run is not UNSET:
            field_dict["dry_run"] = dry_run
        if max_fixes is not UNSET:
            field_dict["max_fixes"] = max_fixes
        if repo_context is not UNSET:
            field_dict["repo_context"] = repo_context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_fix_on_pr_request_findings_item import AutoFixOnPRRequestFindingsItem
        from ..models.auto_fix_on_pr_request_repo_context import AutoFixOnPRRequestRepoContext

        d = dict(src_dict)
        org_id = d.pop("org_id")

        installation_id = d.pop("installation_id")

        repo = d.pop("repo")

        pr_number = d.pop("pr_number")

        def _parse_head_sha(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        head_sha = _parse_head_sha(d.pop("head_sha", UNSET))

        _findings = d.pop("findings", UNSET)
        findings: list[AutoFixOnPRRequestFindingsItem] | Unset = UNSET
        if _findings is not UNSET:
            findings = []
            for findings_item_data in _findings:
                findings_item = AutoFixOnPRRequestFindingsItem.from_dict(findings_item_data)

                findings.append(findings_item)

        dry_run = d.pop("dry_run", UNSET)

        max_fixes = d.pop("max_fixes", UNSET)

        _repo_context = d.pop("repo_context", UNSET)
        repo_context: AutoFixOnPRRequestRepoContext | Unset
        if isinstance(_repo_context, Unset):
            repo_context = UNSET
        else:
            repo_context = AutoFixOnPRRequestRepoContext.from_dict(_repo_context)

        auto_fix_on_pr_request = cls(
            org_id=org_id,
            installation_id=installation_id,
            repo=repo,
            pr_number=pr_number,
            head_sha=head_sha,
            findings=findings,
            dry_run=dry_run,
            max_fixes=max_fixes,
            repo_context=repo_context,
        )

        auto_fix_on_pr_request.additional_properties = d
        return auto_fix_on_pr_request

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
