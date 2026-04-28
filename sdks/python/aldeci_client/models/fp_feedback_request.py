from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FPFeedbackRequest")


@_attrs_define
class FPFeedbackRequest:
    """Submit analyst feedback on a finding.

    Attributes:
        finding_id (str): Finding ID to provide feedback on
        is_false_positive (bool): True if this is a false positive
        reason (str | Unset): Reason for the classification Default: ''.
        scanner (str | Unset): Scanner that produced the finding Default: ''.
        cwe_id (str | Unset): CWE ID of the finding Default: ''.
        app_id (str | Unset): Application ID Default: ''.
        org_id (str | Unset): Organization ID Default: ''.
        rule_id (str | Unset): Rule/check ID that fired Default: ''.
        title (str | Unset): Finding title Default: ''.
        analyst (str | Unset): Analyst who reviewed Default: ''.
    """

    finding_id: str
    is_false_positive: bool
    reason: str | Unset = ""
    scanner: str | Unset = ""
    cwe_id: str | Unset = ""
    app_id: str | Unset = ""
    org_id: str | Unset = ""
    rule_id: str | Unset = ""
    title: str | Unset = ""
    analyst: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        is_false_positive = self.is_false_positive

        reason = self.reason

        scanner = self.scanner

        cwe_id = self.cwe_id

        app_id = self.app_id

        org_id = self.org_id

        rule_id = self.rule_id

        title = self.title

        analyst = self.analyst

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "is_false_positive": is_false_positive,
            }
        )
        if reason is not UNSET:
            field_dict["reason"] = reason
        if scanner is not UNSET:
            field_dict["scanner"] = scanner
        if cwe_id is not UNSET:
            field_dict["cwe_id"] = cwe_id
        if app_id is not UNSET:
            field_dict["app_id"] = app_id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if title is not UNSET:
            field_dict["title"] = title
        if analyst is not UNSET:
            field_dict["analyst"] = analyst

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        is_false_positive = d.pop("is_false_positive")

        reason = d.pop("reason", UNSET)

        scanner = d.pop("scanner", UNSET)

        cwe_id = d.pop("cwe_id", UNSET)

        app_id = d.pop("app_id", UNSET)

        org_id = d.pop("org_id", UNSET)

        rule_id = d.pop("rule_id", UNSET)

        title = d.pop("title", UNSET)

        analyst = d.pop("analyst", UNSET)

        fp_feedback_request = cls(
            finding_id=finding_id,
            is_false_positive=is_false_positive,
            reason=reason,
            scanner=scanner,
            cwe_id=cwe_id,
            app_id=app_id,
            org_id=org_id,
            rule_id=rule_id,
            title=title,
            analyst=analyst,
        )

        fp_feedback_request.additional_properties = d
        return fp_feedback_request

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
