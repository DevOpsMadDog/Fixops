from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ConfigUpdate")


@_attrs_define
class ConfigUpdate:
    """
    Attributes:
        mode (None | str | Unset):
        block_sqli (bool | None | Unset):
        block_xss (bool | None | Unset):
        block_cmdi (bool | None | Unset):
        block_path_traversal (bool | None | Unset):
        block_ssrf (bool | None | Unset):
        block_prototype_pollution (bool | None | Unset):
        block_deserialization (bool | None | Unset):
        block_bots (bool | None | Unset):
        block_zero_day_patterns (bool | None | Unset):
        rate_limit_rpm (int | None | Unset):
        bot_score_threshold (float | None | Unset):
        ip_allowlist (list[str] | None | Unset):
        ip_denylist (list[str] | None | Unset):
    """

    mode: None | str | Unset = UNSET
    block_sqli: bool | None | Unset = UNSET
    block_xss: bool | None | Unset = UNSET
    block_cmdi: bool | None | Unset = UNSET
    block_path_traversal: bool | None | Unset = UNSET
    block_ssrf: bool | None | Unset = UNSET
    block_prototype_pollution: bool | None | Unset = UNSET
    block_deserialization: bool | None | Unset = UNSET
    block_bots: bool | None | Unset = UNSET
    block_zero_day_patterns: bool | None | Unset = UNSET
    rate_limit_rpm: int | None | Unset = UNSET
    bot_score_threshold: float | None | Unset = UNSET
    ip_allowlist: list[str] | None | Unset = UNSET
    ip_denylist: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mode: None | str | Unset
        if isinstance(self.mode, Unset):
            mode = UNSET
        else:
            mode = self.mode

        block_sqli: bool | None | Unset
        if isinstance(self.block_sqli, Unset):
            block_sqli = UNSET
        else:
            block_sqli = self.block_sqli

        block_xss: bool | None | Unset
        if isinstance(self.block_xss, Unset):
            block_xss = UNSET
        else:
            block_xss = self.block_xss

        block_cmdi: bool | None | Unset
        if isinstance(self.block_cmdi, Unset):
            block_cmdi = UNSET
        else:
            block_cmdi = self.block_cmdi

        block_path_traversal: bool | None | Unset
        if isinstance(self.block_path_traversal, Unset):
            block_path_traversal = UNSET
        else:
            block_path_traversal = self.block_path_traversal

        block_ssrf: bool | None | Unset
        if isinstance(self.block_ssrf, Unset):
            block_ssrf = UNSET
        else:
            block_ssrf = self.block_ssrf

        block_prototype_pollution: bool | None | Unset
        if isinstance(self.block_prototype_pollution, Unset):
            block_prototype_pollution = UNSET
        else:
            block_prototype_pollution = self.block_prototype_pollution

        block_deserialization: bool | None | Unset
        if isinstance(self.block_deserialization, Unset):
            block_deserialization = UNSET
        else:
            block_deserialization = self.block_deserialization

        block_bots: bool | None | Unset
        if isinstance(self.block_bots, Unset):
            block_bots = UNSET
        else:
            block_bots = self.block_bots

        block_zero_day_patterns: bool | None | Unset
        if isinstance(self.block_zero_day_patterns, Unset):
            block_zero_day_patterns = UNSET
        else:
            block_zero_day_patterns = self.block_zero_day_patterns

        rate_limit_rpm: int | None | Unset
        if isinstance(self.rate_limit_rpm, Unset):
            rate_limit_rpm = UNSET
        else:
            rate_limit_rpm = self.rate_limit_rpm

        bot_score_threshold: float | None | Unset
        if isinstance(self.bot_score_threshold, Unset):
            bot_score_threshold = UNSET
        else:
            bot_score_threshold = self.bot_score_threshold

        ip_allowlist: list[str] | None | Unset
        if isinstance(self.ip_allowlist, Unset):
            ip_allowlist = UNSET
        elif isinstance(self.ip_allowlist, list):
            ip_allowlist = self.ip_allowlist

        else:
            ip_allowlist = self.ip_allowlist

        ip_denylist: list[str] | None | Unset
        if isinstance(self.ip_denylist, Unset):
            ip_denylist = UNSET
        elif isinstance(self.ip_denylist, list):
            ip_denylist = self.ip_denylist

        else:
            ip_denylist = self.ip_denylist

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if mode is not UNSET:
            field_dict["mode"] = mode
        if block_sqli is not UNSET:
            field_dict["block_sqli"] = block_sqli
        if block_xss is not UNSET:
            field_dict["block_xss"] = block_xss
        if block_cmdi is not UNSET:
            field_dict["block_cmdi"] = block_cmdi
        if block_path_traversal is not UNSET:
            field_dict["block_path_traversal"] = block_path_traversal
        if block_ssrf is not UNSET:
            field_dict["block_ssrf"] = block_ssrf
        if block_prototype_pollution is not UNSET:
            field_dict["block_prototype_pollution"] = block_prototype_pollution
        if block_deserialization is not UNSET:
            field_dict["block_deserialization"] = block_deserialization
        if block_bots is not UNSET:
            field_dict["block_bots"] = block_bots
        if block_zero_day_patterns is not UNSET:
            field_dict["block_zero_day_patterns"] = block_zero_day_patterns
        if rate_limit_rpm is not UNSET:
            field_dict["rate_limit_rpm"] = rate_limit_rpm
        if bot_score_threshold is not UNSET:
            field_dict["bot_score_threshold"] = bot_score_threshold
        if ip_allowlist is not UNSET:
            field_dict["ip_allowlist"] = ip_allowlist
        if ip_denylist is not UNSET:
            field_dict["ip_denylist"] = ip_denylist

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_mode(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        mode = _parse_mode(d.pop("mode", UNSET))

        def _parse_block_sqli(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_sqli = _parse_block_sqli(d.pop("block_sqli", UNSET))

        def _parse_block_xss(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_xss = _parse_block_xss(d.pop("block_xss", UNSET))

        def _parse_block_cmdi(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_cmdi = _parse_block_cmdi(d.pop("block_cmdi", UNSET))

        def _parse_block_path_traversal(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_path_traversal = _parse_block_path_traversal(d.pop("block_path_traversal", UNSET))

        def _parse_block_ssrf(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_ssrf = _parse_block_ssrf(d.pop("block_ssrf", UNSET))

        def _parse_block_prototype_pollution(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_prototype_pollution = _parse_block_prototype_pollution(d.pop("block_prototype_pollution", UNSET))

        def _parse_block_deserialization(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_deserialization = _parse_block_deserialization(d.pop("block_deserialization", UNSET))

        def _parse_block_bots(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_bots = _parse_block_bots(d.pop("block_bots", UNSET))

        def _parse_block_zero_day_patterns(data: object) -> bool | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(bool | None | Unset, data)

        block_zero_day_patterns = _parse_block_zero_day_patterns(d.pop("block_zero_day_patterns", UNSET))

        def _parse_rate_limit_rpm(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        rate_limit_rpm = _parse_rate_limit_rpm(d.pop("rate_limit_rpm", UNSET))

        def _parse_bot_score_threshold(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        bot_score_threshold = _parse_bot_score_threshold(d.pop("bot_score_threshold", UNSET))

        def _parse_ip_allowlist(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                ip_allowlist_type_0 = cast(list[str], data)

                return ip_allowlist_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        ip_allowlist = _parse_ip_allowlist(d.pop("ip_allowlist", UNSET))

        def _parse_ip_denylist(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                ip_denylist_type_0 = cast(list[str], data)

                return ip_denylist_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        ip_denylist = _parse_ip_denylist(d.pop("ip_denylist", UNSET))

        config_update = cls(
            mode=mode,
            block_sqli=block_sqli,
            block_xss=block_xss,
            block_cmdi=block_cmdi,
            block_path_traversal=block_path_traversal,
            block_ssrf=block_ssrf,
            block_prototype_pollution=block_prototype_pollution,
            block_deserialization=block_deserialization,
            block_bots=block_bots,
            block_zero_day_patterns=block_zero_day_patterns,
            rate_limit_rpm=rate_limit_rpm,
            bot_score_threshold=bot_score_threshold,
            ip_allowlist=ip_allowlist,
            ip_denylist=ip_denylist,
        )

        config_update.additional_properties = d
        return config_update

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
