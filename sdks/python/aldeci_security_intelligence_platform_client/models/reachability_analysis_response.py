from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.reachability_analysis_response_result_type_0 import ReachabilityAnalysisResponseResultType0


T = TypeVar("T", bound="ReachabilityAnalysisResponse")


@_attrs_define
class ReachabilityAnalysisResponse:
    """Response from reachability analysis.

    Attributes:
        status (str): Analysis status
        created_at (str): Analysis creation timestamp
        job_id (None | str | Unset): Job ID for async analysis
        result (None | ReachabilityAnalysisResponseResultType0 | Unset): Analysis result
        message (None | str | Unset): Status message
    """

    status: str
    created_at: str
    job_id: None | str | Unset = UNSET
    result: None | ReachabilityAnalysisResponseResultType0 | Unset = UNSET
    message: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.reachability_analysis_response_result_type_0 import ReachabilityAnalysisResponseResultType0

        status = self.status

        created_at = self.created_at

        job_id: None | str | Unset
        if isinstance(self.job_id, Unset):
            job_id = UNSET
        else:
            job_id = self.job_id

        result: dict[str, Any] | None | Unset
        if isinstance(self.result, Unset):
            result = UNSET
        elif isinstance(self.result, ReachabilityAnalysisResponseResultType0):
            result = self.result.to_dict()
        else:
            result = self.result

        message: None | str | Unset
        if isinstance(self.message, Unset):
            message = UNSET
        else:
            message = self.message

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "status": status,
                "created_at": created_at,
            }
        )
        if job_id is not UNSET:
            field_dict["job_id"] = job_id
        if result is not UNSET:
            field_dict["result"] = result
        if message is not UNSET:
            field_dict["message"] = message

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.reachability_analysis_response_result_type_0 import ReachabilityAnalysisResponseResultType0

        d = dict(src_dict)
        status = d.pop("status")

        created_at = d.pop("created_at")

        def _parse_job_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        job_id = _parse_job_id(d.pop("job_id", UNSET))

        def _parse_result(data: object) -> None | ReachabilityAnalysisResponseResultType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                result_type_0 = ReachabilityAnalysisResponseResultType0.from_dict(data)

                return result_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | ReachabilityAnalysisResponseResultType0 | Unset, data)

        result = _parse_result(d.pop("result", UNSET))

        def _parse_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        message = _parse_message(d.pop("message", UNSET))

        reachability_analysis_response = cls(
            status=status,
            created_at=created_at,
            job_id=job_id,
            result=result,
            message=message,
        )

        reachability_analysis_response.additional_properties = d
        return reachability_analysis_response

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
