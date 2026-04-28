from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.stride_category import STRIDECategory
from ..models.threat_status import ThreatStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dread_score import DREADScore


T = TypeVar("T", bound="ThreatEntry")


@_attrs_define
class ThreatEntry:
    """A single threat identified during threat modeling.

    Links a STRIDE category with a DREAD score and tracks mitigation state.

        Attributes:
            title (str): Short threat title
            description (str): Detailed threat description
            stride_category (STRIDECategory): STRIDE threat classification categories.
            affected_component (str): System component at risk
            id (str | Unset):
            dread_score (DREADScore | None | Unset): DREAD risk score
            mitigations (list[str] | Unset): Mitigation controls applied
            status (ThreatStatus | Unset): Lifecycle status of a threat entry.
            org_id (str | Unset): Organisation identifier Default: 'default'.
            created_at (datetime.datetime | Unset):
    """

    title: str
    description: str
    stride_category: STRIDECategory
    affected_component: str
    id: str | Unset = UNSET
    dread_score: DREADScore | None | Unset = UNSET
    mitigations: list[str] | Unset = UNSET
    status: ThreatStatus | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.dread_score import DREADScore

        title = self.title

        description = self.description

        stride_category = self.stride_category.value

        affected_component = self.affected_component

        id = self.id

        dread_score: dict[str, Any] | None | Unset
        if isinstance(self.dread_score, Unset):
            dread_score = UNSET
        elif isinstance(self.dread_score, DREADScore):
            dread_score = self.dread_score.to_dict()
        else:
            dread_score = self.dread_score

        mitigations: list[str] | Unset = UNSET
        if not isinstance(self.mitigations, Unset):
            mitigations = self.mitigations

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        org_id = self.org_id

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
                "description": description,
                "stride_category": stride_category,
                "affected_component": affected_component,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if dread_score is not UNSET:
            field_dict["dread_score"] = dread_score
        if mitigations is not UNSET:
            field_dict["mitigations"] = mitigations
        if status is not UNSET:
            field_dict["status"] = status
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dread_score import DREADScore

        d = dict(src_dict)
        title = d.pop("title")

        description = d.pop("description")

        stride_category = STRIDECategory(d.pop("stride_category"))

        affected_component = d.pop("affected_component")

        id = d.pop("id", UNSET)

        def _parse_dread_score(data: object) -> DREADScore | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                dread_score_type_0 = DREADScore.from_dict(data)

                return dread_score_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DREADScore | None | Unset, data)

        dread_score = _parse_dread_score(d.pop("dread_score", UNSET))

        mitigations = cast(list[str], d.pop("mitigations", UNSET))

        _status = d.pop("status", UNSET)
        status: ThreatStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = ThreatStatus(_status)

        org_id = d.pop("org_id", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        threat_entry = cls(
            title=title,
            description=description,
            stride_category=stride_category,
            affected_component=affected_component,
            id=id,
            dread_score=dread_score,
            mitigations=mitigations,
            status=status,
            org_id=org_id,
            created_at=created_at,
        )

        threat_entry.additional_properties = d
        return threat_entry

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
