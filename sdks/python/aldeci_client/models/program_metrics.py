from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.program_metrics_roi_estimate import ProgramMetricsRoiEstimate
    from ..models.program_metrics_submissions_by_severity import ProgramMetricsSubmissionsBySeverity
    from ..models.program_metrics_submissions_by_status import ProgramMetricsSubmissionsByStatus
    from ..models.program_metrics_top_reporters_item import ProgramMetricsTopReportersItem


T = TypeVar("T", bound="ProgramMetrics")


@_attrs_define
class ProgramMetrics:
    """
    Attributes:
        program_id (str):
        total_submissions (int | Unset):  Default: 0.
        submissions_by_status (ProgramMetricsSubmissionsByStatus | Unset):
        submissions_by_severity (ProgramMetricsSubmissionsBySeverity | Unset):
        acceptance_rate (float | Unset):  Default: 0.0.
        avg_triage_hours (float | Unset):  Default: 0.0.
        avg_fix_hours (float | Unset):  Default: 0.0.
        total_rewards_paid (float | Unset):  Default: 0.0.
        monthly_spend (float | Unset):  Default: 0.0.
        top_reporters (list[ProgramMetricsTopReportersItem] | Unset):
        submissions_this_month (int | Unset):  Default: 0.
        roi_estimate (ProgramMetricsRoiEstimate | Unset):
    """

    program_id: str
    total_submissions: int | Unset = 0
    submissions_by_status: ProgramMetricsSubmissionsByStatus | Unset = UNSET
    submissions_by_severity: ProgramMetricsSubmissionsBySeverity | Unset = UNSET
    acceptance_rate: float | Unset = 0.0
    avg_triage_hours: float | Unset = 0.0
    avg_fix_hours: float | Unset = 0.0
    total_rewards_paid: float | Unset = 0.0
    monthly_spend: float | Unset = 0.0
    top_reporters: list[ProgramMetricsTopReportersItem] | Unset = UNSET
    submissions_this_month: int | Unset = 0
    roi_estimate: ProgramMetricsRoiEstimate | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        program_id = self.program_id

        total_submissions = self.total_submissions

        submissions_by_status: dict[str, Any] | Unset = UNSET
        if not isinstance(self.submissions_by_status, Unset):
            submissions_by_status = self.submissions_by_status.to_dict()

        submissions_by_severity: dict[str, Any] | Unset = UNSET
        if not isinstance(self.submissions_by_severity, Unset):
            submissions_by_severity = self.submissions_by_severity.to_dict()

        acceptance_rate = self.acceptance_rate

        avg_triage_hours = self.avg_triage_hours

        avg_fix_hours = self.avg_fix_hours

        total_rewards_paid = self.total_rewards_paid

        monthly_spend = self.monthly_spend

        top_reporters: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.top_reporters, Unset):
            top_reporters = []
            for top_reporters_item_data in self.top_reporters:
                top_reporters_item = top_reporters_item_data.to_dict()
                top_reporters.append(top_reporters_item)

        submissions_this_month = self.submissions_this_month

        roi_estimate: dict[str, Any] | Unset = UNSET
        if not isinstance(self.roi_estimate, Unset):
            roi_estimate = self.roi_estimate.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "program_id": program_id,
            }
        )
        if total_submissions is not UNSET:
            field_dict["total_submissions"] = total_submissions
        if submissions_by_status is not UNSET:
            field_dict["submissions_by_status"] = submissions_by_status
        if submissions_by_severity is not UNSET:
            field_dict["submissions_by_severity"] = submissions_by_severity
        if acceptance_rate is not UNSET:
            field_dict["acceptance_rate"] = acceptance_rate
        if avg_triage_hours is not UNSET:
            field_dict["avg_triage_hours"] = avg_triage_hours
        if avg_fix_hours is not UNSET:
            field_dict["avg_fix_hours"] = avg_fix_hours
        if total_rewards_paid is not UNSET:
            field_dict["total_rewards_paid"] = total_rewards_paid
        if monthly_spend is not UNSET:
            field_dict["monthly_spend"] = monthly_spend
        if top_reporters is not UNSET:
            field_dict["top_reporters"] = top_reporters
        if submissions_this_month is not UNSET:
            field_dict["submissions_this_month"] = submissions_this_month
        if roi_estimate is not UNSET:
            field_dict["roi_estimate"] = roi_estimate

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.program_metrics_roi_estimate import ProgramMetricsRoiEstimate
        from ..models.program_metrics_submissions_by_severity import ProgramMetricsSubmissionsBySeverity
        from ..models.program_metrics_submissions_by_status import ProgramMetricsSubmissionsByStatus
        from ..models.program_metrics_top_reporters_item import ProgramMetricsTopReportersItem

        d = dict(src_dict)
        program_id = d.pop("program_id")

        total_submissions = d.pop("total_submissions", UNSET)

        _submissions_by_status = d.pop("submissions_by_status", UNSET)
        submissions_by_status: ProgramMetricsSubmissionsByStatus | Unset
        if isinstance(_submissions_by_status, Unset):
            submissions_by_status = UNSET
        else:
            submissions_by_status = ProgramMetricsSubmissionsByStatus.from_dict(_submissions_by_status)

        _submissions_by_severity = d.pop("submissions_by_severity", UNSET)
        submissions_by_severity: ProgramMetricsSubmissionsBySeverity | Unset
        if isinstance(_submissions_by_severity, Unset):
            submissions_by_severity = UNSET
        else:
            submissions_by_severity = ProgramMetricsSubmissionsBySeverity.from_dict(_submissions_by_severity)

        acceptance_rate = d.pop("acceptance_rate", UNSET)

        avg_triage_hours = d.pop("avg_triage_hours", UNSET)

        avg_fix_hours = d.pop("avg_fix_hours", UNSET)

        total_rewards_paid = d.pop("total_rewards_paid", UNSET)

        monthly_spend = d.pop("monthly_spend", UNSET)

        _top_reporters = d.pop("top_reporters", UNSET)
        top_reporters: list[ProgramMetricsTopReportersItem] | Unset = UNSET
        if _top_reporters is not UNSET:
            top_reporters = []
            for top_reporters_item_data in _top_reporters:
                top_reporters_item = ProgramMetricsTopReportersItem.from_dict(top_reporters_item_data)

                top_reporters.append(top_reporters_item)

        submissions_this_month = d.pop("submissions_this_month", UNSET)

        _roi_estimate = d.pop("roi_estimate", UNSET)
        roi_estimate: ProgramMetricsRoiEstimate | Unset
        if isinstance(_roi_estimate, Unset):
            roi_estimate = UNSET
        else:
            roi_estimate = ProgramMetricsRoiEstimate.from_dict(_roi_estimate)

        program_metrics = cls(
            program_id=program_id,
            total_submissions=total_submissions,
            submissions_by_status=submissions_by_status,
            submissions_by_severity=submissions_by_severity,
            acceptance_rate=acceptance_rate,
            avg_triage_hours=avg_triage_hours,
            avg_fix_hours=avg_fix_hours,
            total_rewards_paid=total_rewards_paid,
            monthly_spend=monthly_spend,
            top_reporters=top_reporters,
            submissions_this_month=submissions_this_month,
            roi_estimate=roi_estimate,
        )

        program_metrics.additional_properties = d
        return program_metrics

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
