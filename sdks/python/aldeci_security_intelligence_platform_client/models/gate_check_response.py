from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.gate_check_detail import GateCheckDetail
    from ..models.gate_check_response_policy_violations_item import GateCheckResponsePolicyViolationsItem


T = TypeVar("T", bound="GateCheckResponse")


@_attrs_define
class GateCheckResponse:
    """Gate evaluation response — the CI system consumes this.

    Attributes:
        gate_id (str): Unique evaluation ID
        passed (bool): Binary pass/fail — the CI exit code
        verdict (str): PASS | FAIL | WARN
        reason (str): Human-readable summary
        repository (str):
        commit_sha (str):
        branch (str):
        evaluated_at (str): ISO 8601 timestamp
        pull_request (int | None | Unset):
        findings_count (int | Unset): Total findings evaluated Default: 0.
        policy_violations (list[GateCheckResponsePolicyViolationsItem] | Unset):
        checks (list[GateCheckDetail] | Unset):
        checks_passed (int | Unset):  Default: 0.
        checks_failed (int | Unset):  Default: 0.
        checks_warned (int | Unset):  Default: 0.
        checks_skipped (int | Unset):  Default: 0.
        evaluation_ms (float | Unset): Evaluation duration in milliseconds Default: 0.0.
    """

    gate_id: str
    passed: bool
    verdict: str
    reason: str
    repository: str
    commit_sha: str
    branch: str
    evaluated_at: str
    pull_request: int | None | Unset = UNSET
    findings_count: int | Unset = 0
    policy_violations: list[GateCheckResponsePolicyViolationsItem] | Unset = UNSET
    checks: list[GateCheckDetail] | Unset = UNSET
    checks_passed: int | Unset = 0
    checks_failed: int | Unset = 0
    checks_warned: int | Unset = 0
    checks_skipped: int | Unset = 0
    evaluation_ms: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        gate_id = self.gate_id

        passed = self.passed

        verdict = self.verdict

        reason = self.reason

        repository = self.repository

        commit_sha = self.commit_sha

        branch = self.branch

        evaluated_at = self.evaluated_at

        pull_request: int | None | Unset
        if isinstance(self.pull_request, Unset):
            pull_request = UNSET
        else:
            pull_request = self.pull_request

        findings_count = self.findings_count

        policy_violations: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.policy_violations, Unset):
            policy_violations = []
            for policy_violations_item_data in self.policy_violations:
                policy_violations_item = policy_violations_item_data.to_dict()
                policy_violations.append(policy_violations_item)

        checks: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.checks, Unset):
            checks = []
            for checks_item_data in self.checks:
                checks_item = checks_item_data.to_dict()
                checks.append(checks_item)

        checks_passed = self.checks_passed

        checks_failed = self.checks_failed

        checks_warned = self.checks_warned

        checks_skipped = self.checks_skipped

        evaluation_ms = self.evaluation_ms

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "gate_id": gate_id,
                "passed": passed,
                "verdict": verdict,
                "reason": reason,
                "repository": repository,
                "commit_sha": commit_sha,
                "branch": branch,
                "evaluated_at": evaluated_at,
            }
        )
        if pull_request is not UNSET:
            field_dict["pull_request"] = pull_request
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if policy_violations is not UNSET:
            field_dict["policy_violations"] = policy_violations
        if checks is not UNSET:
            field_dict["checks"] = checks
        if checks_passed is not UNSET:
            field_dict["checks_passed"] = checks_passed
        if checks_failed is not UNSET:
            field_dict["checks_failed"] = checks_failed
        if checks_warned is not UNSET:
            field_dict["checks_warned"] = checks_warned
        if checks_skipped is not UNSET:
            field_dict["checks_skipped"] = checks_skipped
        if evaluation_ms is not UNSET:
            field_dict["evaluation_ms"] = evaluation_ms

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gate_check_detail import GateCheckDetail
        from ..models.gate_check_response_policy_violations_item import GateCheckResponsePolicyViolationsItem

        d = dict(src_dict)
        gate_id = d.pop("gate_id")

        passed = d.pop("passed")

        verdict = d.pop("verdict")

        reason = d.pop("reason")

        repository = d.pop("repository")

        commit_sha = d.pop("commit_sha")

        branch = d.pop("branch")

        evaluated_at = d.pop("evaluated_at")

        def _parse_pull_request(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        pull_request = _parse_pull_request(d.pop("pull_request", UNSET))

        findings_count = d.pop("findings_count", UNSET)

        _policy_violations = d.pop("policy_violations", UNSET)
        policy_violations: list[GateCheckResponsePolicyViolationsItem] | Unset = UNSET
        if _policy_violations is not UNSET:
            policy_violations = []
            for policy_violations_item_data in _policy_violations:
                policy_violations_item = GateCheckResponsePolicyViolationsItem.from_dict(policy_violations_item_data)

                policy_violations.append(policy_violations_item)

        _checks = d.pop("checks", UNSET)
        checks: list[GateCheckDetail] | Unset = UNSET
        if _checks is not UNSET:
            checks = []
            for checks_item_data in _checks:
                checks_item = GateCheckDetail.from_dict(checks_item_data)

                checks.append(checks_item)

        checks_passed = d.pop("checks_passed", UNSET)

        checks_failed = d.pop("checks_failed", UNSET)

        checks_warned = d.pop("checks_warned", UNSET)

        checks_skipped = d.pop("checks_skipped", UNSET)

        evaluation_ms = d.pop("evaluation_ms", UNSET)

        gate_check_response = cls(
            gate_id=gate_id,
            passed=passed,
            verdict=verdict,
            reason=reason,
            repository=repository,
            commit_sha=commit_sha,
            branch=branch,
            evaluated_at=evaluated_at,
            pull_request=pull_request,
            findings_count=findings_count,
            policy_violations=policy_violations,
            checks=checks,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            checks_warned=checks_warned,
            checks_skipped=checks_skipped,
            evaluation_ms=evaluation_ms,
        )

        gate_check_response.additional_properties = d
        return gate_check_response

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
