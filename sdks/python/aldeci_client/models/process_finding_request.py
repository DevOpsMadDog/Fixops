from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.process_finding_request_finding import ProcessFindingRequestFinding


T = TypeVar("T", bound="ProcessFindingRequest")


@_attrs_define
class ProcessFindingRequest:
    """Request to process a single finding.

    Attributes:
        finding (ProcessFindingRequestFinding):
        run_id (str):
        org_id (str):
        source (str | Unset):  Default: 'sarif'.
    """

    finding: ProcessFindingRequestFinding
    run_id: str
    org_id: str
    source: str | Unset = "sarif"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        run_id = self.run_id

        org_id = self.org_id

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
                "run_id": run_id,
                "org_id": org_id,
            }
        )
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.process_finding_request_finding import ProcessFindingRequestFinding

        d = dict(src_dict)
        finding = ProcessFindingRequestFinding.from_dict(d.pop("finding"))

        run_id = d.pop("run_id")

        org_id = d.pop("org_id")

        source = d.pop("source", UNSET)

        process_finding_request = cls(
            finding=finding,
            run_id=run_id,
            org_id=org_id,
            source=source,
        )

        process_finding_request.additional_properties = d
        return process_finding_request

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
