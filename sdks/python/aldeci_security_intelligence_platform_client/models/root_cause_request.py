from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.root_cause_request_evidence import RootCauseRequestEvidence


T = TypeVar("T", bound="RootCauseRequest")


@_attrs_define
class RootCauseRequest:
    """Request for root cause identification.

    Attributes:
        symptom (str | Unset): SecurityFactor symptom to trace back from Default: 'attack_successful'.
        evidence (RootCauseRequestEvidence | Unset): Map of SecurityFactor names to their boolean state
    """

    symptom: str | Unset = "attack_successful"
    evidence: RootCauseRequestEvidence | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        symptom = self.symptom

        evidence: dict[str, Any] | Unset = UNSET
        if not isinstance(self.evidence, Unset):
            evidence = self.evidence.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if symptom is not UNSET:
            field_dict["symptom"] = symptom
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.root_cause_request_evidence import RootCauseRequestEvidence

        d = dict(src_dict)
        symptom = d.pop("symptom", UNSET)

        _evidence = d.pop("evidence", UNSET)
        evidence: RootCauseRequestEvidence | Unset
        if isinstance(_evidence, Unset):
            evidence = UNSET
        else:
            evidence = RootCauseRequestEvidence.from_dict(_evidence)

        root_cause_request = cls(
            symptom=symptom,
            evidence=evidence,
        )

        root_cause_request.additional_properties = d
        return root_cause_request

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
