from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.contribution_program import ContributionProgram
from ..types import UNSET, Unset

T = TypeVar("T", bound="ContributeResponse")


@_attrs_define
class ContributeResponse:
    """Response for CVE contribution submission.

    Attributes:
        submission_id (str):
        vuln_id (str):
        program (ContributionProgram): CVE contribution programs.
        status (str):
        cve_id (None | str | Unset):
        estimated_assignment_date (None | str | Unset):
        tracking_url (None | str | Unset):
    """

    submission_id: str
    vuln_id: str
    program: ContributionProgram
    status: str
    cve_id: None | str | Unset = UNSET
    estimated_assignment_date: None | str | Unset = UNSET
    tracking_url: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        submission_id = self.submission_id

        vuln_id = self.vuln_id

        program = self.program.value

        status = self.status

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        estimated_assignment_date: None | str | Unset
        if isinstance(self.estimated_assignment_date, Unset):
            estimated_assignment_date = UNSET
        else:
            estimated_assignment_date = self.estimated_assignment_date

        tracking_url: None | str | Unset
        if isinstance(self.tracking_url, Unset):
            tracking_url = UNSET
        else:
            tracking_url = self.tracking_url

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "submission_id": submission_id,
                "vuln_id": vuln_id,
                "program": program,
                "status": status,
            }
        )
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if estimated_assignment_date is not UNSET:
            field_dict["estimated_assignment_date"] = estimated_assignment_date
        if tracking_url is not UNSET:
            field_dict["tracking_url"] = tracking_url

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        submission_id = d.pop("submission_id")

        vuln_id = d.pop("vuln_id")

        program = ContributionProgram(d.pop("program"))

        status = d.pop("status")

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_estimated_assignment_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        estimated_assignment_date = _parse_estimated_assignment_date(d.pop("estimated_assignment_date", UNSET))

        def _parse_tracking_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tracking_url = _parse_tracking_url(d.pop("tracking_url", UNSET))

        contribute_response = cls(
            submission_id=submission_id,
            vuln_id=vuln_id,
            program=program,
            status=status,
            cve_id=cve_id,
            estimated_assignment_date=estimated_assignment_date,
            tracking_url=tracking_url,
        )

        contribute_response.additional_properties = d
        return contribute_response

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
