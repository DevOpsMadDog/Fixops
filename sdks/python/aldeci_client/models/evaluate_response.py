from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.gate_verdict import GateVerdict

if TYPE_CHECKING:
    from ..models.evaluate_response_blocking_findings_item import EvaluateResponseBlockingFindingsItem
    from ..models.evaluate_response_findings_by_severity import EvaluateResponseFindingsBySeverity
    from ..models.evaluate_response_warning_findings_item import EvaluateResponseWarningFindingsItem
    from ..models.gating_policy import GatingPolicy


T = TypeVar("T", bound="EvaluateResponse")


@_attrs_define
class EvaluateResponse:
    """Result of gate evaluation.

    Attributes:
        verdict (GateVerdict):
        exit_code (int): 0=pass, 1=fail, 2=warn
        summary (str):
        findings_total (int):
        findings_by_severity (EvaluateResponseFindingsBySeverity):
        blocking_findings (list[EvaluateResponseBlockingFindingsItem]):
        warning_findings (list[EvaluateResponseWarningFindingsItem]):
        policy_applied (GatingPolicy): Policy that determines pass/fail for PR and CI/CD gates.
        evaluation_id (str):
        evaluated_at (str):
    """

    verdict: GateVerdict
    exit_code: int
    summary: str
    findings_total: int
    findings_by_severity: EvaluateResponseFindingsBySeverity
    blocking_findings: list[EvaluateResponseBlockingFindingsItem]
    warning_findings: list[EvaluateResponseWarningFindingsItem]
    policy_applied: GatingPolicy
    evaluation_id: str
    evaluated_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        verdict = self.verdict.value

        exit_code = self.exit_code

        summary = self.summary

        findings_total = self.findings_total

        findings_by_severity = self.findings_by_severity.to_dict()

        blocking_findings = []
        for blocking_findings_item_data in self.blocking_findings:
            blocking_findings_item = blocking_findings_item_data.to_dict()
            blocking_findings.append(blocking_findings_item)

        warning_findings = []
        for warning_findings_item_data in self.warning_findings:
            warning_findings_item = warning_findings_item_data.to_dict()
            warning_findings.append(warning_findings_item)

        policy_applied = self.policy_applied.to_dict()

        evaluation_id = self.evaluation_id

        evaluated_at = self.evaluated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "verdict": verdict,
                "exit_code": exit_code,
                "summary": summary,
                "findings_total": findings_total,
                "findings_by_severity": findings_by_severity,
                "blocking_findings": blocking_findings,
                "warning_findings": warning_findings,
                "policy_applied": policy_applied,
                "evaluation_id": evaluation_id,
                "evaluated_at": evaluated_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_response_blocking_findings_item import EvaluateResponseBlockingFindingsItem
        from ..models.evaluate_response_findings_by_severity import EvaluateResponseFindingsBySeverity
        from ..models.evaluate_response_warning_findings_item import EvaluateResponseWarningFindingsItem
        from ..models.gating_policy import GatingPolicy

        d = dict(src_dict)
        verdict = GateVerdict(d.pop("verdict"))

        exit_code = d.pop("exit_code")

        summary = d.pop("summary")

        findings_total = d.pop("findings_total")

        findings_by_severity = EvaluateResponseFindingsBySeverity.from_dict(d.pop("findings_by_severity"))

        blocking_findings = []
        _blocking_findings = d.pop("blocking_findings")
        for blocking_findings_item_data in _blocking_findings:
            blocking_findings_item = EvaluateResponseBlockingFindingsItem.from_dict(blocking_findings_item_data)

            blocking_findings.append(blocking_findings_item)

        warning_findings = []
        _warning_findings = d.pop("warning_findings")
        for warning_findings_item_data in _warning_findings:
            warning_findings_item = EvaluateResponseWarningFindingsItem.from_dict(warning_findings_item_data)

            warning_findings.append(warning_findings_item)

        policy_applied = GatingPolicy.from_dict(d.pop("policy_applied"))

        evaluation_id = d.pop("evaluation_id")

        evaluated_at = d.pop("evaluated_at")

        evaluate_response = cls(
            verdict=verdict,
            exit_code=exit_code,
            summary=summary,
            findings_total=findings_total,
            findings_by_severity=findings_by_severity,
            blocking_findings=blocking_findings,
            warning_findings=warning_findings,
            policy_applied=policy_applied,
            evaluation_id=evaluation_id,
            evaluated_at=evaluated_at,
        )

        evaluate_response.additional_properties = d
        return evaluate_response

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
