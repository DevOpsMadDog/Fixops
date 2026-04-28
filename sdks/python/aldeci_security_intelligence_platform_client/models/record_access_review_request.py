from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAccessReviewRequest")


@_attrs_define
class RecordAccessReviewRequest:
    """
    Attributes:
        identity_id (str):
        org_id (str | Unset):  Default: 'default'.
        reviewer (str | Unset):  Default: ''.
        review_type (str | Unset):  Default: 'periodic'.
        outcome (str | Unset):  Default: 'no_action'.
        findings (list[str] | Unset):
        reviewed_at (None | str | Unset):
    """

    identity_id: str
    org_id: str | Unset = "default"
    reviewer: str | Unset = ""
    review_type: str | Unset = "periodic"
    outcome: str | Unset = "no_action"
    findings: list[str] | Unset = UNSET
    reviewed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        identity_id = self.identity_id

        org_id = self.org_id

        reviewer = self.reviewer

        review_type = self.review_type

        outcome = self.outcome

        findings: list[str] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = self.findings

        reviewed_at: None | str | Unset
        if isinstance(self.reviewed_at, Unset):
            reviewed_at = UNSET
        else:
            reviewed_at = self.reviewed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "identity_id": identity_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if reviewer is not UNSET:
            field_dict["reviewer"] = reviewer
        if review_type is not UNSET:
            field_dict["review_type"] = review_type
        if outcome is not UNSET:
            field_dict["outcome"] = outcome
        if findings is not UNSET:
            field_dict["findings"] = findings
        if reviewed_at is not UNSET:
            field_dict["reviewed_at"] = reviewed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        identity_id = d.pop("identity_id")

        org_id = d.pop("org_id", UNSET)

        reviewer = d.pop("reviewer", UNSET)

        review_type = d.pop("review_type", UNSET)

        outcome = d.pop("outcome", UNSET)

        findings = cast(list[str], d.pop("findings", UNSET))

        def _parse_reviewed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reviewed_at = _parse_reviewed_at(d.pop("reviewed_at", UNSET))

        record_access_review_request = cls(
            identity_id=identity_id,
            org_id=org_id,
            reviewer=reviewer,
            review_type=review_type,
            outcome=outcome,
            findings=findings,
            reviewed_at=reviewed_at,
        )

        record_access_review_request.additional_properties = d
        return record_access_review_request

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
