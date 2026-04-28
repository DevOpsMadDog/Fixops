from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.drift_response_new_assets_item import DriftResponseNewAssetsItem
    from ..models.drift_response_removed_assets_item import DriftResponseRemovedAssetsItem


T = TypeVar("T", bound="DriftResponse")


@_attrs_define
class DriftResponse:
    """
    Attributes:
        lookback_days (int):
        new_count (int):
        removed_count (int):
        new_assets (list[DriftResponseNewAssetsItem]):
        removed_assets (list[DriftResponseRemovedAssetsItem]):
    """

    lookback_days: int
    new_count: int
    removed_count: int
    new_assets: list[DriftResponseNewAssetsItem]
    removed_assets: list[DriftResponseRemovedAssetsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        lookback_days = self.lookback_days

        new_count = self.new_count

        removed_count = self.removed_count

        new_assets = []
        for new_assets_item_data in self.new_assets:
            new_assets_item = new_assets_item_data.to_dict()
            new_assets.append(new_assets_item)

        removed_assets = []
        for removed_assets_item_data in self.removed_assets:
            removed_assets_item = removed_assets_item_data.to_dict()
            removed_assets.append(removed_assets_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "lookback_days": lookback_days,
                "new_count": new_count,
                "removed_count": removed_count,
                "new_assets": new_assets,
                "removed_assets": removed_assets,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.drift_response_new_assets_item import DriftResponseNewAssetsItem
        from ..models.drift_response_removed_assets_item import DriftResponseRemovedAssetsItem

        d = dict(src_dict)
        lookback_days = d.pop("lookback_days")

        new_count = d.pop("new_count")

        removed_count = d.pop("removed_count")

        new_assets = []
        _new_assets = d.pop("new_assets")
        for new_assets_item_data in _new_assets:
            new_assets_item = DriftResponseNewAssetsItem.from_dict(new_assets_item_data)

            new_assets.append(new_assets_item)

        removed_assets = []
        _removed_assets = d.pop("removed_assets")
        for removed_assets_item_data in _removed_assets:
            removed_assets_item = DriftResponseRemovedAssetsItem.from_dict(removed_assets_item_data)

            removed_assets.append(removed_assets_item)

        drift_response = cls(
            lookback_days=lookback_days,
            new_count=new_count,
            removed_count=removed_count,
            new_assets=new_assets,
            removed_assets=removed_assets,
        )

        drift_response.additional_properties = d
        return drift_response

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
