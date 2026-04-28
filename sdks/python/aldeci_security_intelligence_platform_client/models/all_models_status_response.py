from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.all_models_status_response_models import AllModelsStatusResponseModels
    from ..models.all_models_status_response_store_stats import AllModelsStatusResponseStoreStats


T = TypeVar("T", bound="AllModelsStatusResponse")


@_attrs_define
class AllModelsStatusResponse:
    """Status of all ML models.

    Attributes:
        models (AllModelsStatusResponseModels):
        store_stats (AllModelsStatusResponseStoreStats | Unset):
    """

    models: AllModelsStatusResponseModels
    store_stats: AllModelsStatusResponseStoreStats | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        models = self.models.to_dict()

        store_stats: dict[str, Any] | Unset = UNSET
        if not isinstance(self.store_stats, Unset):
            store_stats = self.store_stats.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "models": models,
            }
        )
        if store_stats is not UNSET:
            field_dict["store_stats"] = store_stats

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.all_models_status_response_models import AllModelsStatusResponseModels
        from ..models.all_models_status_response_store_stats import AllModelsStatusResponseStoreStats

        d = dict(src_dict)
        models = AllModelsStatusResponseModels.from_dict(d.pop("models"))

        _store_stats = d.pop("store_stats", UNSET)
        store_stats: AllModelsStatusResponseStoreStats | Unset
        if isinstance(_store_stats, Unset):
            store_stats = UNSET
        else:
            store_stats = AllModelsStatusResponseStoreStats.from_dict(_store_stats)

        all_models_status_response = cls(
            models=models,
            store_stats=store_stats,
        )

        all_models_status_response.additional_properties = d
        return all_models_status_response

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
