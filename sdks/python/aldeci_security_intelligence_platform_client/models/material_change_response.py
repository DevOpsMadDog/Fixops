from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.material_change_response_blast_radius_type_0 import MaterialChangeResponseBlastRadiusType0


T = TypeVar("T", bound="MaterialChangeResponse")


@_attrs_define
class MaterialChangeResponse:
    """Response from push-event analysis.

    Attributes:
        id (str):
        commit_sha (str):
        repository (str):
        branch (str):
        author (str):
        changed_files_count (int):
        blast_radius (MaterialChangeResponseBlastRadiusType0 | None):
        sast_findings_count (int):
        is_material (bool):
        materiality_reasons (list[str]):
        incident_id (None | str):
        analyzed_at (str):
    """

    id: str
    commit_sha: str
    repository: str
    branch: str
    author: str
    changed_files_count: int
    blast_radius: MaterialChangeResponseBlastRadiusType0 | None
    sast_findings_count: int
    is_material: bool
    materiality_reasons: list[str]
    incident_id: None | str
    analyzed_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.material_change_response_blast_radius_type_0 import MaterialChangeResponseBlastRadiusType0

        id = self.id

        commit_sha = self.commit_sha

        repository = self.repository

        branch = self.branch

        author = self.author

        changed_files_count = self.changed_files_count

        blast_radius: dict[str, Any] | None
        if isinstance(self.blast_radius, MaterialChangeResponseBlastRadiusType0):
            blast_radius = self.blast_radius.to_dict()
        else:
            blast_radius = self.blast_radius

        sast_findings_count = self.sast_findings_count

        is_material = self.is_material

        materiality_reasons = self.materiality_reasons

        incident_id: None | str
        incident_id = self.incident_id

        analyzed_at = self.analyzed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "id": id,
                "commit_sha": commit_sha,
                "repository": repository,
                "branch": branch,
                "author": author,
                "changed_files_count": changed_files_count,
                "blast_radius": blast_radius,
                "sast_findings_count": sast_findings_count,
                "is_material": is_material,
                "materiality_reasons": materiality_reasons,
                "incident_id": incident_id,
                "analyzed_at": analyzed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.material_change_response_blast_radius_type_0 import MaterialChangeResponseBlastRadiusType0

        d = dict(src_dict)
        id = d.pop("id")

        commit_sha = d.pop("commit_sha")

        repository = d.pop("repository")

        branch = d.pop("branch")

        author = d.pop("author")

        changed_files_count = d.pop("changed_files_count")

        def _parse_blast_radius(data: object) -> MaterialChangeResponseBlastRadiusType0 | None:
            if data is None:
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                blast_radius_type_0 = MaterialChangeResponseBlastRadiusType0.from_dict(data)

                return blast_radius_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(MaterialChangeResponseBlastRadiusType0 | None, data)

        blast_radius = _parse_blast_radius(d.pop("blast_radius"))

        sast_findings_count = d.pop("sast_findings_count")

        is_material = d.pop("is_material")

        materiality_reasons = cast(list[str], d.pop("materiality_reasons"))

        def _parse_incident_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        incident_id = _parse_incident_id(d.pop("incident_id"))

        analyzed_at = d.pop("analyzed_at")

        material_change_response = cls(
            id=id,
            commit_sha=commit_sha,
            repository=repository,
            branch=branch,
            author=author,
            changed_files_count=changed_files_count,
            blast_radius=blast_radius,
            sast_findings_count=sast_findings_count,
            is_material=is_material,
            materiality_reasons=materiality_reasons,
            incident_id=incident_id,
            analyzed_at=analyzed_at,
        )

        material_change_response.additional_properties = d
        return material_change_response

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
