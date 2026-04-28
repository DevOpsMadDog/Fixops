from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LiveFeedbackRequest")


@_attrs_define
class LiveFeedbackRequest:
    """Submit a single feedback item for any loop and immediately see the scoring effect.

    Attributes:
        loop (str): Loop name: decision, mpte, fp, remediation, policy
        decision_id (str | Unset): Decision ID (for decision loop) Default: ''.
        finding_id (str | Unset): Finding ID Default: ''.
        predicted_action (str | Unset): What AI decided Default: 'FIX'.
        actual_outcome (str | Unset): What actually happened Default: 'FIX'.
        predicted_exploitable (bool | Unset): Was it predicted exploitable? Default: True.
        actual_exploitable (bool | Unset): Was it actually exploitable? Default: True.
        mpte_confidence (float | Unset):  Default: 0.8.
        scanner (str | Unset): Scanner name Default: 'semgrep'.
        rule_id (str | Unset): Rule ID Default: 'CWE-89'.
        is_false_positive (bool | Unset): Is this a false positive? Default: False.
        fix_type (str | Unset): Fix type Default: 'CODE_PATCH'.
        fix_applied (str | Unset): Fix description Default: 'Applied fix'.
        resolved (bool | Unset): Did the fix resolve the issue? Default: True.
        time_to_fix_hours (float | Unset):  Default: 2.0.
        policy_id (str | Unset): Policy ID Default: 'POL-001'.
        violated (bool | Unset): Was the policy violated? Default: True.
        was_justified (bool | Unset): Was the violation justified? Default: False.
        cvss_score (float | Unset):  Default: 7.5.
        epss_score (float | Unset):  Default: 0.35.
        in_kev (bool | Unset):  Default: False.
        asset_criticality (float | Unset):  Default: 0.7.
    """

    loop: str
    decision_id: str | Unset = ""
    finding_id: str | Unset = ""
    predicted_action: str | Unset = "FIX"
    actual_outcome: str | Unset = "FIX"
    predicted_exploitable: bool | Unset = True
    actual_exploitable: bool | Unset = True
    mpte_confidence: float | Unset = 0.8
    scanner: str | Unset = "semgrep"
    rule_id: str | Unset = "CWE-89"
    is_false_positive: bool | Unset = False
    fix_type: str | Unset = "CODE_PATCH"
    fix_applied: str | Unset = "Applied fix"
    resolved: bool | Unset = True
    time_to_fix_hours: float | Unset = 2.0
    policy_id: str | Unset = "POL-001"
    violated: bool | Unset = True
    was_justified: bool | Unset = False
    cvss_score: float | Unset = 7.5
    epss_score: float | Unset = 0.35
    in_kev: bool | Unset = False
    asset_criticality: float | Unset = 0.7
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        loop = self.loop

        decision_id = self.decision_id

        finding_id = self.finding_id

        predicted_action = self.predicted_action

        actual_outcome = self.actual_outcome

        predicted_exploitable = self.predicted_exploitable

        actual_exploitable = self.actual_exploitable

        mpte_confidence = self.mpte_confidence

        scanner = self.scanner

        rule_id = self.rule_id

        is_false_positive = self.is_false_positive

        fix_type = self.fix_type

        fix_applied = self.fix_applied

        resolved = self.resolved

        time_to_fix_hours = self.time_to_fix_hours

        policy_id = self.policy_id

        violated = self.violated

        was_justified = self.was_justified

        cvss_score = self.cvss_score

        epss_score = self.epss_score

        in_kev = self.in_kev

        asset_criticality = self.asset_criticality

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "loop": loop,
            }
        )
        if decision_id is not UNSET:
            field_dict["decision_id"] = decision_id
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if predicted_action is not UNSET:
            field_dict["predicted_action"] = predicted_action
        if actual_outcome is not UNSET:
            field_dict["actual_outcome"] = actual_outcome
        if predicted_exploitable is not UNSET:
            field_dict["predicted_exploitable"] = predicted_exploitable
        if actual_exploitable is not UNSET:
            field_dict["actual_exploitable"] = actual_exploitable
        if mpte_confidence is not UNSET:
            field_dict["mpte_confidence"] = mpte_confidence
        if scanner is not UNSET:
            field_dict["scanner"] = scanner
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if is_false_positive is not UNSET:
            field_dict["is_false_positive"] = is_false_positive
        if fix_type is not UNSET:
            field_dict["fix_type"] = fix_type
        if fix_applied is not UNSET:
            field_dict["fix_applied"] = fix_applied
        if resolved is not UNSET:
            field_dict["resolved"] = resolved
        if time_to_fix_hours is not UNSET:
            field_dict["time_to_fix_hours"] = time_to_fix_hours
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if violated is not UNSET:
            field_dict["violated"] = violated
        if was_justified is not UNSET:
            field_dict["was_justified"] = was_justified
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if in_kev is not UNSET:
            field_dict["in_kev"] = in_kev
        if asset_criticality is not UNSET:
            field_dict["asset_criticality"] = asset_criticality

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        loop = d.pop("loop")

        decision_id = d.pop("decision_id", UNSET)

        finding_id = d.pop("finding_id", UNSET)

        predicted_action = d.pop("predicted_action", UNSET)

        actual_outcome = d.pop("actual_outcome", UNSET)

        predicted_exploitable = d.pop("predicted_exploitable", UNSET)

        actual_exploitable = d.pop("actual_exploitable", UNSET)

        mpte_confidence = d.pop("mpte_confidence", UNSET)

        scanner = d.pop("scanner", UNSET)

        rule_id = d.pop("rule_id", UNSET)

        is_false_positive = d.pop("is_false_positive", UNSET)

        fix_type = d.pop("fix_type", UNSET)

        fix_applied = d.pop("fix_applied", UNSET)

        resolved = d.pop("resolved", UNSET)

        time_to_fix_hours = d.pop("time_to_fix_hours", UNSET)

        policy_id = d.pop("policy_id", UNSET)

        violated = d.pop("violated", UNSET)

        was_justified = d.pop("was_justified", UNSET)

        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        in_kev = d.pop("in_kev", UNSET)

        asset_criticality = d.pop("asset_criticality", UNSET)

        live_feedback_request = cls(
            loop=loop,
            decision_id=decision_id,
            finding_id=finding_id,
            predicted_action=predicted_action,
            actual_outcome=actual_outcome,
            predicted_exploitable=predicted_exploitable,
            actual_exploitable=actual_exploitable,
            mpte_confidence=mpte_confidence,
            scanner=scanner,
            rule_id=rule_id,
            is_false_positive=is_false_positive,
            fix_type=fix_type,
            fix_applied=fix_applied,
            resolved=resolved,
            time_to_fix_hours=time_to_fix_hours,
            policy_id=policy_id,
            violated=violated,
            was_justified=was_justified,
            cvss_score=cvss_score,
            epss_score=epss_score,
            in_kev=in_kev,
            asset_criticality=asset_criticality,
        )

        live_feedback_request.additional_properties = d
        return live_feedback_request

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
