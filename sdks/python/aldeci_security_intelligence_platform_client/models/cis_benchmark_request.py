from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.cis_benchmark_request_config_snapshot import CISBenchmarkRequestConfigSnapshot


T = TypeVar("T", bound="CISBenchmarkRequest")


@_attrs_define
class CISBenchmarkRequest:
    """POST /compliance/cis — run CIS Docker Benchmark checks.

    Attributes:
        target (str | Unset):  Default: 'docker-host'.
        config_snapshot (CISBenchmarkRequestConfigSnapshot | Unset): Keys: docker_daemon, container_opts, host_info,
            image_analysis
        section_filter (None | str | Unset):
    """

    target: str | Unset = "docker-host"
    config_snapshot: CISBenchmarkRequestConfigSnapshot | Unset = UNSET
    section_filter: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target

        config_snapshot: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config_snapshot, Unset):
            config_snapshot = self.config_snapshot.to_dict()

        section_filter: None | str | Unset
        if isinstance(self.section_filter, Unset):
            section_filter = UNSET
        else:
            section_filter = self.section_filter

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if target is not UNSET:
            field_dict["target"] = target
        if config_snapshot is not UNSET:
            field_dict["config_snapshot"] = config_snapshot
        if section_filter is not UNSET:
            field_dict["section_filter"] = section_filter

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.cis_benchmark_request_config_snapshot import CISBenchmarkRequestConfigSnapshot

        d = dict(src_dict)
        target = d.pop("target", UNSET)

        _config_snapshot = d.pop("config_snapshot", UNSET)
        config_snapshot: CISBenchmarkRequestConfigSnapshot | Unset
        if isinstance(_config_snapshot, Unset):
            config_snapshot = UNSET
        else:
            config_snapshot = CISBenchmarkRequestConfigSnapshot.from_dict(_config_snapshot)

        def _parse_section_filter(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        section_filter = _parse_section_filter(d.pop("section_filter", UNSET))

        cis_benchmark_request = cls(
            target=target,
            config_snapshot=config_snapshot,
            section_filter=section_filter,
        )

        cis_benchmark_request.additional_properties = d
        return cis_benchmark_request

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
