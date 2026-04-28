from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.dast_ingest_zap_request_report import DastIngestZapRequestReport


T = TypeVar("T", bound="DastIngestZapRequest")


@_attrs_define
class DastIngestZapRequest:
    """Ingest a parsed ZAP JSON report (no Docker required).

    Attributes:
        org_id (str):
        report (DastIngestZapRequestReport): Parsed ZAP JSON report (zap-baseline.py -J output)
        target (None | str | Unset):
        scan_id (None | str | Unset):
        mirror_to_bug_bounty (bool | Unset):  Default: True.
    """

    org_id: str
    report: DastIngestZapRequestReport
    target: None | str | Unset = UNSET
    scan_id: None | str | Unset = UNSET
    mirror_to_bug_bounty: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        report = self.report.to_dict()

        target: None | str | Unset
        if isinstance(self.target, Unset):
            target = UNSET
        else:
            target = self.target

        scan_id: None | str | Unset
        if isinstance(self.scan_id, Unset):
            scan_id = UNSET
        else:
            scan_id = self.scan_id

        mirror_to_bug_bounty = self.mirror_to_bug_bounty

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "report": report,
            }
        )
        if target is not UNSET:
            field_dict["target"] = target
        if scan_id is not UNSET:
            field_dict["scan_id"] = scan_id
        if mirror_to_bug_bounty is not UNSET:
            field_dict["mirror_to_bug_bounty"] = mirror_to_bug_bounty

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.dast_ingest_zap_request_report import DastIngestZapRequestReport

        d = dict(src_dict)
        org_id = d.pop("org_id")

        report = DastIngestZapRequestReport.from_dict(d.pop("report"))

        def _parse_target(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target = _parse_target(d.pop("target", UNSET))

        def _parse_scan_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        scan_id = _parse_scan_id(d.pop("scan_id", UNSET))

        mirror_to_bug_bounty = d.pop("mirror_to_bug_bounty", UNSET)

        dast_ingest_zap_request = cls(
            org_id=org_id,
            report=report,
            target=target,
            scan_id=scan_id,
            mirror_to_bug_bounty=mirror_to_bug_bounty,
        )

        dast_ingest_zap_request.additional_properties = d
        return dast_ingest_zap_request

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
