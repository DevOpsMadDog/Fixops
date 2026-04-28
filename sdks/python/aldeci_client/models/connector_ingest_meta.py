from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConnectorIngestMeta")


@_attrs_define
class ConnectorIngestMeta:
    """Metadata about the ingest request.

    Attributes:
        connector_version (str): Connector version
        pull_timestamp (datetime.datetime): When findings were pulled from source
        page_number (int | None | Unset): Current page in paginated pull
        page_size (int | None | Unset): Findings per page
        total_pages (int | None | Unset): Total pages in pull
        api_endpoint (None | str | Unset): Source API endpoint queried
    """

    connector_version: str
    pull_timestamp: datetime.datetime
    page_number: int | None | Unset = UNSET
    page_size: int | None | Unset = UNSET
    total_pages: int | None | Unset = UNSET
    api_endpoint: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        connector_version = self.connector_version

        pull_timestamp = self.pull_timestamp.isoformat()

        page_number: int | None | Unset
        if isinstance(self.page_number, Unset):
            page_number = UNSET
        else:
            page_number = self.page_number

        page_size: int | None | Unset
        if isinstance(self.page_size, Unset):
            page_size = UNSET
        else:
            page_size = self.page_size

        total_pages: int | None | Unset
        if isinstance(self.total_pages, Unset):
            total_pages = UNSET
        else:
            total_pages = self.total_pages

        api_endpoint: None | str | Unset
        if isinstance(self.api_endpoint, Unset):
            api_endpoint = UNSET
        else:
            api_endpoint = self.api_endpoint

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "connector_version": connector_version,
                "pull_timestamp": pull_timestamp,
            }
        )
        if page_number is not UNSET:
            field_dict["page_number"] = page_number
        if page_size is not UNSET:
            field_dict["page_size"] = page_size
        if total_pages is not UNSET:
            field_dict["total_pages"] = total_pages
        if api_endpoint is not UNSET:
            field_dict["api_endpoint"] = api_endpoint

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        connector_version = d.pop("connector_version")

        pull_timestamp = isoparse(d.pop("pull_timestamp"))

        def _parse_page_number(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        page_number = _parse_page_number(d.pop("page_number", UNSET))

        def _parse_page_size(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        page_size = _parse_page_size(d.pop("page_size", UNSET))

        def _parse_total_pages(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        total_pages = _parse_total_pages(d.pop("total_pages", UNSET))

        def _parse_api_endpoint(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        api_endpoint = _parse_api_endpoint(d.pop("api_endpoint", UNSET))

        connector_ingest_meta = cls(
            connector_version=connector_version,
            pull_timestamp=pull_timestamp,
            page_number=page_number,
            page_size=page_size,
            total_pages=total_pages,
            api_endpoint=api_endpoint,
        )

        connector_ingest_meta.additional_properties = d
        return connector_ingest_meta

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
