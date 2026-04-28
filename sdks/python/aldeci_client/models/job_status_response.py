from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.job_status_response_errors_item import JobStatusResponseErrorsItem
    from ..models.job_status_response_results_type_0_item import JobStatusResponseResultsType0Item


T = TypeVar("T", bound="JobStatusResponse")


@_attrs_define
class JobStatusResponse:
    """Response model for job status.

    Attributes:
        job_id (str):
        status (str):
        action_type (str):
        total_items (int):
        processed_items (int):
        success_count (int):
        failure_count (int):
        progress_percent (float):
        started_at (str):
        completed_at (None | str | Unset):
        results (list[JobStatusResponseResultsType0Item] | None | Unset):
        errors (list[JobStatusResponseErrorsItem] | Unset):
    """

    job_id: str
    status: str
    action_type: str
    total_items: int
    processed_items: int
    success_count: int
    failure_count: int
    progress_percent: float
    started_at: str
    completed_at: None | str | Unset = UNSET
    results: list[JobStatusResponseResultsType0Item] | None | Unset = UNSET
    errors: list[JobStatusResponseErrorsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        job_id = self.job_id

        status = self.status

        action_type = self.action_type

        total_items = self.total_items

        processed_items = self.processed_items

        success_count = self.success_count

        failure_count = self.failure_count

        progress_percent = self.progress_percent

        started_at = self.started_at

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        results: list[dict[str, Any]] | None | Unset
        if isinstance(self.results, Unset):
            results = UNSET
        elif isinstance(self.results, list):
            results = []
            for results_type_0_item_data in self.results:
                results_type_0_item = results_type_0_item_data.to_dict()
                results.append(results_type_0_item)

        else:
            results = self.results

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "job_id": job_id,
                "status": status,
                "action_type": action_type,
                "total_items": total_items,
                "processed_items": processed_items,
                "success_count": success_count,
                "failure_count": failure_count,
                "progress_percent": progress_percent,
                "started_at": started_at,
            }
        )
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if results is not UNSET:
            field_dict["results"] = results
        if errors is not UNSET:
            field_dict["errors"] = errors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.job_status_response_errors_item import JobStatusResponseErrorsItem
        from ..models.job_status_response_results_type_0_item import JobStatusResponseResultsType0Item

        d = dict(src_dict)
        job_id = d.pop("job_id")

        status = d.pop("status")

        action_type = d.pop("action_type")

        total_items = d.pop("total_items")

        processed_items = d.pop("processed_items")

        success_count = d.pop("success_count")

        failure_count = d.pop("failure_count")

        progress_percent = d.pop("progress_percent")

        started_at = d.pop("started_at")

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        def _parse_results(data: object) -> list[JobStatusResponseResultsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                results_type_0 = []
                _results_type_0 = data
                for results_type_0_item_data in _results_type_0:
                    results_type_0_item = JobStatusResponseResultsType0Item.from_dict(results_type_0_item_data)

                    results_type_0.append(results_type_0_item)

                return results_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[JobStatusResponseResultsType0Item] | None | Unset, data)

        results = _parse_results(d.pop("results", UNSET))

        _errors = d.pop("errors", UNSET)
        errors: list[JobStatusResponseErrorsItem] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = JobStatusResponseErrorsItem.from_dict(errors_item_data)

                errors.append(errors_item)

        job_status_response = cls(
            job_id=job_id,
            status=status,
            action_type=action_type,
            total_items=total_items,
            processed_items=processed_items,
            success_count=success_count,
            failure_count=failure_count,
            progress_percent=progress_percent,
            started_at=started_at,
            completed_at=completed_at,
            results=results,
            errors=errors,
        )

        job_status_response.additional_properties = d
        return job_status_response

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
