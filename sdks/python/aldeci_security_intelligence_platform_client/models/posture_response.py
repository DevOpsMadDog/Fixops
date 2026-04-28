from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.posture_response_details import PostureResponseDetails


T = TypeVar("T", bound="PostureResponse")


@_attrs_define
class PostureResponse:
    """
    Attributes:
        provider (str):
        account_id (str):
        score (float):
        total_controls (int):
        passed_controls (int):
        failed_controls (int):
        critical_findings (int):
        high_findings (int):
        medium_findings (int):
        low_findings (int):
        generated_at (str):
        region (None | str | Unset):
        frameworks (list[str] | Unset):
        details (PostureResponseDetails | Unset):
    """

    provider: str
    account_id: str
    score: float
    total_controls: int
    passed_controls: int
    failed_controls: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    generated_at: str
    region: None | str | Unset = UNSET
    frameworks: list[str] | Unset = UNSET
    details: PostureResponseDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        provider = self.provider

        account_id = self.account_id

        score = self.score

        total_controls = self.total_controls

        passed_controls = self.passed_controls

        failed_controls = self.failed_controls

        critical_findings = self.critical_findings

        high_findings = self.high_findings

        medium_findings = self.medium_findings

        low_findings = self.low_findings

        generated_at = self.generated_at

        region: None | str | Unset
        if isinstance(self.region, Unset):
            region = UNSET
        else:
            region = self.region

        frameworks: list[str] | Unset = UNSET
        if not isinstance(self.frameworks, Unset):
            frameworks = self.frameworks

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "provider": provider,
                "account_id": account_id,
                "score": score,
                "total_controls": total_controls,
                "passed_controls": passed_controls,
                "failed_controls": failed_controls,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "medium_findings": medium_findings,
                "low_findings": low_findings,
                "generated_at": generated_at,
            }
        )
        if region is not UNSET:
            field_dict["region"] = region
        if frameworks is not UNSET:
            field_dict["frameworks"] = frameworks
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.posture_response_details import PostureResponseDetails

        d = dict(src_dict)
        provider = d.pop("provider")

        account_id = d.pop("account_id")

        score = d.pop("score")

        total_controls = d.pop("total_controls")

        passed_controls = d.pop("passed_controls")

        failed_controls = d.pop("failed_controls")

        critical_findings = d.pop("critical_findings")

        high_findings = d.pop("high_findings")

        medium_findings = d.pop("medium_findings")

        low_findings = d.pop("low_findings")

        generated_at = d.pop("generated_at")

        def _parse_region(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        region = _parse_region(d.pop("region", UNSET))

        frameworks = cast(list[str], d.pop("frameworks", UNSET))

        _details = d.pop("details", UNSET)
        details: PostureResponseDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = PostureResponseDetails.from_dict(_details)

        posture_response = cls(
            provider=provider,
            account_id=account_id,
            score=score,
            total_controls=total_controls,
            passed_controls=passed_controls,
            failed_controls=failed_controls,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            generated_at=generated_at,
            region=region,
            frameworks=frameworks,
            details=details,
        )

        posture_response.additional_properties = d
        return posture_response

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
