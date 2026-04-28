from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.channel import Channel
from ..models.digest_frequency import DigestFrequency
from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdatePreferenceRequest")


@_attrs_define
class UpdatePreferenceRequest:
    """
    Attributes:
        channels (list[Channel] | None | Unset):
        digest_frequency (DigestFrequency | None | Unset):
        muted_sources (list[str] | None | Unset):
        quiet_hours_start (int | None | Unset):
        quiet_hours_end (int | None | Unset):
    """

    channels: list[Channel] | None | Unset = UNSET
    digest_frequency: DigestFrequency | None | Unset = UNSET
    muted_sources: list[str] | None | Unset = UNSET
    quiet_hours_start: int | None | Unset = UNSET
    quiet_hours_end: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        channels: list[str] | None | Unset
        if isinstance(self.channels, Unset):
            channels = UNSET
        elif isinstance(self.channels, list):
            channels = []
            for channels_type_0_item_data in self.channels:
                channels_type_0_item = channels_type_0_item_data.value
                channels.append(channels_type_0_item)

        else:
            channels = self.channels

        digest_frequency: None | str | Unset
        if isinstance(self.digest_frequency, Unset):
            digest_frequency = UNSET
        elif isinstance(self.digest_frequency, DigestFrequency):
            digest_frequency = self.digest_frequency.value
        else:
            digest_frequency = self.digest_frequency

        muted_sources: list[str] | None | Unset
        if isinstance(self.muted_sources, Unset):
            muted_sources = UNSET
        elif isinstance(self.muted_sources, list):
            muted_sources = self.muted_sources

        else:
            muted_sources = self.muted_sources

        quiet_hours_start: int | None | Unset
        if isinstance(self.quiet_hours_start, Unset):
            quiet_hours_start = UNSET
        else:
            quiet_hours_start = self.quiet_hours_start

        quiet_hours_end: int | None | Unset
        if isinstance(self.quiet_hours_end, Unset):
            quiet_hours_end = UNSET
        else:
            quiet_hours_end = self.quiet_hours_end

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if channels is not UNSET:
            field_dict["channels"] = channels
        if digest_frequency is not UNSET:
            field_dict["digest_frequency"] = digest_frequency
        if muted_sources is not UNSET:
            field_dict["muted_sources"] = muted_sources
        if quiet_hours_start is not UNSET:
            field_dict["quiet_hours_start"] = quiet_hours_start
        if quiet_hours_end is not UNSET:
            field_dict["quiet_hours_end"] = quiet_hours_end

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_channels(data: object) -> list[Channel] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                channels_type_0 = []
                _channels_type_0 = data
                for channels_type_0_item_data in _channels_type_0:
                    channels_type_0_item = Channel(channels_type_0_item_data)

                    channels_type_0.append(channels_type_0_item)

                return channels_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[Channel] | None | Unset, data)

        channels = _parse_channels(d.pop("channels", UNSET))

        def _parse_digest_frequency(data: object) -> DigestFrequency | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                digest_frequency_type_0 = DigestFrequency(data)

                return digest_frequency_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DigestFrequency | None | Unset, data)

        digest_frequency = _parse_digest_frequency(d.pop("digest_frequency", UNSET))

        def _parse_muted_sources(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                muted_sources_type_0 = cast(list[str], data)

                return muted_sources_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        muted_sources = _parse_muted_sources(d.pop("muted_sources", UNSET))

        def _parse_quiet_hours_start(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        quiet_hours_start = _parse_quiet_hours_start(d.pop("quiet_hours_start", UNSET))

        def _parse_quiet_hours_end(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        quiet_hours_end = _parse_quiet_hours_end(d.pop("quiet_hours_end", UNSET))

        update_preference_request = cls(
            channels=channels,
            digest_frequency=digest_frequency,
            muted_sources=muted_sources,
            quiet_hours_start=quiet_hours_start,
            quiet_hours_end=quiet_hours_end,
        )

        update_preference_request.additional_properties = d
        return update_preference_request

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
