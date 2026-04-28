from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.connector_status import ConnectorStatus
from ..models.sdlc_stage import SDLCStage
from ..types import UNSET, Unset

T = TypeVar("T", bound="ConnectorMetadata")


@_attrs_define
class ConnectorMetadata:
    """Metadata for a registered connector.

    Attributes:
        name (str): Connector name
        display_name (str): Display name
        description (str): Connector description
        type_ (str): Connector type (e.g. 'github', 'jira', 'defectdojo')
        stages (list[SDLCStage]): SDLC stages covered
        status (ConnectorStatus): Connector health status.
        version (str): Connector version
        last_pull_time (datetime.datetime | None | Unset): Last successful pull timestamp
        last_pull_findings_count (int | None | Unset): Findings from last pull
        pull_interval_seconds (int | None | Unset): Recommended pull interval
    """

    name: str
    display_name: str
    description: str
    type_: str
    stages: list[SDLCStage]
    status: ConnectorStatus
    version: str
    last_pull_time: datetime.datetime | None | Unset = UNSET
    last_pull_findings_count: int | None | Unset = UNSET
    pull_interval_seconds: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        display_name = self.display_name

        description = self.description

        type_ = self.type_

        stages = []
        for stages_item_data in self.stages:
            stages_item = stages_item_data.value
            stages.append(stages_item)

        status = self.status.value

        version = self.version

        last_pull_time: None | str | Unset
        if isinstance(self.last_pull_time, Unset):
            last_pull_time = UNSET
        elif isinstance(self.last_pull_time, datetime.datetime):
            last_pull_time = self.last_pull_time.isoformat()
        else:
            last_pull_time = self.last_pull_time

        last_pull_findings_count: int | None | Unset
        if isinstance(self.last_pull_findings_count, Unset):
            last_pull_findings_count = UNSET
        else:
            last_pull_findings_count = self.last_pull_findings_count

        pull_interval_seconds: int | None | Unset
        if isinstance(self.pull_interval_seconds, Unset):
            pull_interval_seconds = UNSET
        else:
            pull_interval_seconds = self.pull_interval_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "display_name": display_name,
                "description": description,
                "type": type_,
                "stages": stages,
                "status": status,
                "version": version,
            }
        )
        if last_pull_time is not UNSET:
            field_dict["last_pull_time"] = last_pull_time
        if last_pull_findings_count is not UNSET:
            field_dict["last_pull_findings_count"] = last_pull_findings_count
        if pull_interval_seconds is not UNSET:
            field_dict["pull_interval_seconds"] = pull_interval_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        display_name = d.pop("display_name")

        description = d.pop("description")

        type_ = d.pop("type")

        stages = []
        _stages = d.pop("stages")
        for stages_item_data in _stages:
            stages_item = SDLCStage(stages_item_data)

            stages.append(stages_item)

        status = ConnectorStatus(d.pop("status"))

        version = d.pop("version")

        def _parse_last_pull_time(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                last_pull_time_type_0 = isoparse(data)

                return last_pull_time_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        last_pull_time = _parse_last_pull_time(d.pop("last_pull_time", UNSET))

        def _parse_last_pull_findings_count(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        last_pull_findings_count = _parse_last_pull_findings_count(d.pop("last_pull_findings_count", UNSET))

        def _parse_pull_interval_seconds(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        pull_interval_seconds = _parse_pull_interval_seconds(d.pop("pull_interval_seconds", UNSET))

        connector_metadata = cls(
            name=name,
            display_name=display_name,
            description=description,
            type_=type_,
            stages=stages,
            status=status,
            version=version,
            last_pull_time=last_pull_time,
            last_pull_findings_count=last_pull_findings_count,
            pull_interval_seconds=pull_interval_seconds,
        )

        connector_metadata.additional_properties = d
        return connector_metadata

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
