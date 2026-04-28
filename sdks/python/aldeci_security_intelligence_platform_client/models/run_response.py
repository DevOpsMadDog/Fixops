from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.run_response_report import RunResponseReport


T = TypeVar("T", bound="RunResponse")


@_attrs_define
class RunResponse:
    """
    Attributes:
        run_id (str):
        started_at (str):
        base_url (str):
        status (str):
        total_probes (int):
        vulnerable_count (int):
        report (RunResponseReport):
    """

    run_id: str
    started_at: str
    base_url: str
    status: str
    total_probes: int
    vulnerable_count: int
    report: RunResponseReport
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        run_id = self.run_id

        started_at = self.started_at

        base_url = self.base_url

        status = self.status

        total_probes = self.total_probes

        vulnerable_count = self.vulnerable_count

        report = self.report.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "run_id": run_id,
                "started_at": started_at,
                "base_url": base_url,
                "status": status,
                "total_probes": total_probes,
                "vulnerable_count": vulnerable_count,
                "report": report,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.run_response_report import RunResponseReport

        d = dict(src_dict)
        run_id = d.pop("run_id")

        started_at = d.pop("started_at")

        base_url = d.pop("base_url")

        status = d.pop("status")

        total_probes = d.pop("total_probes")

        vulnerable_count = d.pop("vulnerable_count")

        report = RunResponseReport.from_dict(d.pop("report"))

        run_response = cls(
            run_id=run_id,
            started_at=started_at,
            base_url=base_url,
            status=status,
            total_probes=total_probes,
            vulnerable_count=vulnerable_count,
            report=report,
        )

        run_response.additional_properties = d
        return run_response

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
