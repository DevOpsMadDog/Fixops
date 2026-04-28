from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.token_bucket_stats_response_buckets import TokenBucketStatsResponseBuckets
    from ..models.token_bucket_stats_response_config import TokenBucketStatsResponseConfig


T = TypeVar("T", bound="TokenBucketStatsResponse")


@_attrs_define
class TokenBucketStatsResponse:
    """
    Attributes:
        tracked_keys (int):
        buckets (TokenBucketStatsResponseBuckets):
        config (TokenBucketStatsResponseConfig):
        warning (None | str | Unset):
    """

    tracked_keys: int
    buckets: TokenBucketStatsResponseBuckets
    config: TokenBucketStatsResponseConfig
    warning: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tracked_keys = self.tracked_keys

        buckets = self.buckets.to_dict()

        config = self.config.to_dict()

        warning: None | str | Unset
        if isinstance(self.warning, Unset):
            warning = UNSET
        else:
            warning = self.warning

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tracked_keys": tracked_keys,
                "buckets": buckets,
                "config": config,
            }
        )
        if warning is not UNSET:
            field_dict["warning"] = warning

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.token_bucket_stats_response_buckets import TokenBucketStatsResponseBuckets
        from ..models.token_bucket_stats_response_config import TokenBucketStatsResponseConfig

        d = dict(src_dict)
        tracked_keys = d.pop("tracked_keys")

        buckets = TokenBucketStatsResponseBuckets.from_dict(d.pop("buckets"))

        config = TokenBucketStatsResponseConfig.from_dict(d.pop("config"))

        def _parse_warning(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        warning = _parse_warning(d.pop("warning", UNSET))

        token_bucket_stats_response = cls(
            tracked_keys=tracked_keys,
            buckets=buckets,
            config=config,
            warning=warning,
        )

        token_bucket_stats_response.additional_properties = d
        return token_bucket_stats_response

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
