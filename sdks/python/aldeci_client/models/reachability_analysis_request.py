from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.git_repository_request import GitRepositoryRequest
    from ..models.vulnerability_request import VulnerabilityRequest


T = TypeVar("T", bound="ReachabilityAnalysisRequest")


@_attrs_define
class ReachabilityAnalysisRequest:
    """Request for reachability analysis.

    Attributes:
        repository (GitRepositoryRequest): Git repository configuration.
        vulnerability (VulnerabilityRequest): Vulnerability details for analysis.
        force_refresh (bool | Unset): Force repository refresh Default: False.
        async_analysis (bool | Unset): Run analysis asynchronously Default: True.
    """

    repository: GitRepositoryRequest
    vulnerability: VulnerabilityRequest
    force_refresh: bool | Unset = False
    async_analysis: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repository = self.repository.to_dict()

        vulnerability = self.vulnerability.to_dict()

        force_refresh = self.force_refresh

        async_analysis = self.async_analysis

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repository": repository,
                "vulnerability": vulnerability,
            }
        )
        if force_refresh is not UNSET:
            field_dict["force_refresh"] = force_refresh
        if async_analysis is not UNSET:
            field_dict["async_analysis"] = async_analysis

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.git_repository_request import GitRepositoryRequest
        from ..models.vulnerability_request import VulnerabilityRequest

        d = dict(src_dict)
        repository = GitRepositoryRequest.from_dict(d.pop("repository"))

        vulnerability = VulnerabilityRequest.from_dict(d.pop("vulnerability"))

        force_refresh = d.pop("force_refresh", UNSET)

        async_analysis = d.pop("async_analysis", UNSET)

        reachability_analysis_request = cls(
            repository=repository,
            vulnerability=vulnerability,
            force_refresh=force_refresh,
            async_analysis=async_analysis,
        )

        reachability_analysis_request.additional_properties = d
        return reachability_analysis_request

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
