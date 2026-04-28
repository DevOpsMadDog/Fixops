from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.connector_ingest_meta import ConnectorIngestMeta
    from ..models.normalized_finding import NormalizedFinding


T = TypeVar("T", bound="IngestPayload")


@_attrs_define
class IngestPayload:
    """Main request body for POST /api/v1/connectors/ingest.

    Attributes:
        source (str): Connector name (e.g., 'github', 'jira')
        findings (list[NormalizedFinding]): List of normalized findings
        metadata (ConnectorIngestMeta): Metadata about the ingest request.
    """

    source: str
    findings: list[NormalizedFinding]
    metadata: ConnectorIngestMeta
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source = self.source

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        metadata = self.metadata.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source": source,
                "findings": findings,
                "metadata": metadata,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.connector_ingest_meta import ConnectorIngestMeta
        from ..models.normalized_finding import NormalizedFinding

        d = dict(src_dict)
        source = d.pop("source")

        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = NormalizedFinding.from_dict(findings_item_data)

            findings.append(findings_item)

        metadata = ConnectorIngestMeta.from_dict(d.pop("metadata"))

        ingest_payload = cls(
            source=source,
            findings=findings,
            metadata=metadata,
        )

        ingest_payload.additional_properties = d
        return ingest_payload

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
