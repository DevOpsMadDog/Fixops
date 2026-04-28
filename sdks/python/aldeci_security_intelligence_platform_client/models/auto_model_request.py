from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AutoModelRequest")


@_attrs_define
class AutoModelRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        doc_ingest_id (str): Design-doc ingest id
        model_name (None | str | Unset): Override auto-generated model name
        created_by (str | Unset): Creator id / username Default: 'auto-ingest'.
        link_cyber_model_id (None | str | Unset): If provided, also write traceability link to this cyber model
    """

    org_id: str
    doc_ingest_id: str
    model_name: None | str | Unset = UNSET
    created_by: str | Unset = "auto-ingest"
    link_cyber_model_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        doc_ingest_id = self.doc_ingest_id

        model_name: None | str | Unset
        if isinstance(self.model_name, Unset):
            model_name = UNSET
        else:
            model_name = self.model_name

        created_by = self.created_by

        link_cyber_model_id: None | str | Unset
        if isinstance(self.link_cyber_model_id, Unset):
            link_cyber_model_id = UNSET
        else:
            link_cyber_model_id = self.link_cyber_model_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "doc_ingest_id": doc_ingest_id,
            }
        )
        if model_name is not UNSET:
            field_dict["model_name"] = model_name
        if created_by is not UNSET:
            field_dict["created_by"] = created_by
        if link_cyber_model_id is not UNSET:
            field_dict["link_cyber_model_id"] = link_cyber_model_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        doc_ingest_id = d.pop("doc_ingest_id")

        def _parse_model_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        model_name = _parse_model_name(d.pop("model_name", UNSET))

        created_by = d.pop("created_by", UNSET)

        def _parse_link_cyber_model_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        link_cyber_model_id = _parse_link_cyber_model_id(d.pop("link_cyber_model_id", UNSET))

        auto_model_request = cls(
            org_id=org_id,
            doc_ingest_id=doc_ingest_id,
            model_name=model_name,
            created_by=created_by,
            link_cyber_model_id=link_cyber_model_id,
        )

        auto_model_request.additional_properties = d
        return auto_model_request

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
