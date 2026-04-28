from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.run_hunt_request_findings_item import RunHuntRequestFindingsItem
    from ..models.run_hunt_request_iocs_type_0_item import RunHuntRequestIocsType0Item


T = TypeVar("T", bound="RunHuntRequest")


@_attrs_define
class RunHuntRequest:
    """
    Attributes:
        query_id (str): Built-in or custom query ID
        findings (list[RunHuntRequestFindingsItem] | Unset):
        iocs (list[RunHuntRequestIocsType0Item] | None | Unset): IOC list for correlation
    """

    query_id: str
    findings: list[RunHuntRequestFindingsItem] | Unset = UNSET
    iocs: list[RunHuntRequestIocsType0Item] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        query_id = self.query_id

        findings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.findings, Unset):
            findings = []
            for findings_item_data in self.findings:
                findings_item = findings_item_data.to_dict()
                findings.append(findings_item)

        iocs: list[dict[str, Any]] | None | Unset
        if isinstance(self.iocs, Unset):
            iocs = UNSET
        elif isinstance(self.iocs, list):
            iocs = []
            for iocs_type_0_item_data in self.iocs:
                iocs_type_0_item = iocs_type_0_item_data.to_dict()
                iocs.append(iocs_type_0_item)

        else:
            iocs = self.iocs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "query_id": query_id,
            }
        )
        if findings is not UNSET:
            field_dict["findings"] = findings
        if iocs is not UNSET:
            field_dict["iocs"] = iocs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.run_hunt_request_findings_item import RunHuntRequestFindingsItem
        from ..models.run_hunt_request_iocs_type_0_item import RunHuntRequestIocsType0Item

        d = dict(src_dict)
        query_id = d.pop("query_id")

        _findings = d.pop("findings", UNSET)
        findings: list[RunHuntRequestFindingsItem] | Unset = UNSET
        if _findings is not UNSET:
            findings = []
            for findings_item_data in _findings:
                findings_item = RunHuntRequestFindingsItem.from_dict(findings_item_data)

                findings.append(findings_item)

        def _parse_iocs(data: object) -> list[RunHuntRequestIocsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                iocs_type_0 = []
                _iocs_type_0 = data
                for iocs_type_0_item_data in _iocs_type_0:
                    iocs_type_0_item = RunHuntRequestIocsType0Item.from_dict(iocs_type_0_item_data)

                    iocs_type_0.append(iocs_type_0_item)

                return iocs_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[RunHuntRequestIocsType0Item] | None | Unset, data)

        iocs = _parse_iocs(d.pop("iocs", UNSET))

        run_hunt_request = cls(
            query_id=query_id,
            findings=findings,
            iocs=iocs,
        )

        run_hunt_request.additional_properties = d
        return run_hunt_request

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
