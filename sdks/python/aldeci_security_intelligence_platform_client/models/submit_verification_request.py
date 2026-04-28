from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.submit_verification_request_evidence_data import SubmitVerificationRequestEvidenceData


T = TypeVar("T", bound="SubmitVerificationRequest")


@_attrs_define
class SubmitVerificationRequest:
    """Request to submit verification evidence.

    Attributes:
        evidence_type (str):
        evidence_data (SubmitVerificationRequestEvidenceData):
        submitted_by (None | str | Unset):
    """

    evidence_type: str
    evidence_data: SubmitVerificationRequestEvidenceData
    submitted_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        evidence_type = self.evidence_type

        evidence_data = self.evidence_data.to_dict()

        submitted_by: None | str | Unset
        if isinstance(self.submitted_by, Unset):
            submitted_by = UNSET
        else:
            submitted_by = self.submitted_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "evidence_type": evidence_type,
                "evidence_data": evidence_data,
            }
        )
        if submitted_by is not UNSET:
            field_dict["submitted_by"] = submitted_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.submit_verification_request_evidence_data import SubmitVerificationRequestEvidenceData

        d = dict(src_dict)
        evidence_type = d.pop("evidence_type")

        evidence_data = SubmitVerificationRequestEvidenceData.from_dict(d.pop("evidence_data"))

        def _parse_submitted_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        submitted_by = _parse_submitted_by(d.pop("submitted_by", UNSET))

        submit_verification_request = cls(
            evidence_type=evidence_type,
            evidence_data=evidence_data,
            submitted_by=submitted_by,
        )

        submit_verification_request.additional_properties = d
        return submit_verification_request

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
