from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.context_evaluate_request_crosswalk_item import ContextEvaluateRequestCrosswalkItem
    from ..models.context_evaluate_request_design_rows_item import ContextEvaluateRequestDesignRowsItem
    from ..models.context_evaluate_request_settings import ContextEvaluateRequestSettings


T = TypeVar("T", bound="ContextEvaluateRequest")


@_attrs_define
class ContextEvaluateRequest:
    """
    Attributes:
        org_id (str):
        design_rows (list[ContextEvaluateRequestDesignRowsItem]):
        settings (ContextEvaluateRequestSettings | Unset):
        crosswalk (list[ContextEvaluateRequestCrosswalkItem] | Unset):
    """

    org_id: str
    design_rows: list[ContextEvaluateRequestDesignRowsItem]
    settings: ContextEvaluateRequestSettings | Unset = UNSET
    crosswalk: list[ContextEvaluateRequestCrosswalkItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        design_rows = []
        for design_rows_item_data in self.design_rows:
            design_rows_item = design_rows_item_data.to_dict()
            design_rows.append(design_rows_item)

        settings: dict[str, Any] | Unset = UNSET
        if not isinstance(self.settings, Unset):
            settings = self.settings.to_dict()

        crosswalk: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.crosswalk, Unset):
            crosswalk = []
            for crosswalk_item_data in self.crosswalk:
                crosswalk_item = crosswalk_item_data.to_dict()
                crosswalk.append(crosswalk_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "design_rows": design_rows,
            }
        )
        if settings is not UNSET:
            field_dict["settings"] = settings
        if crosswalk is not UNSET:
            field_dict["crosswalk"] = crosswalk

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.context_evaluate_request_crosswalk_item import ContextEvaluateRequestCrosswalkItem
        from ..models.context_evaluate_request_design_rows_item import ContextEvaluateRequestDesignRowsItem
        from ..models.context_evaluate_request_settings import ContextEvaluateRequestSettings

        d = dict(src_dict)
        org_id = d.pop("org_id")

        design_rows = []
        _design_rows = d.pop("design_rows")
        for design_rows_item_data in _design_rows:
            design_rows_item = ContextEvaluateRequestDesignRowsItem.from_dict(design_rows_item_data)

            design_rows.append(design_rows_item)

        _settings = d.pop("settings", UNSET)
        settings: ContextEvaluateRequestSettings | Unset
        if isinstance(_settings, Unset):
            settings = UNSET
        else:
            settings = ContextEvaluateRequestSettings.from_dict(_settings)

        _crosswalk = d.pop("crosswalk", UNSET)
        crosswalk: list[ContextEvaluateRequestCrosswalkItem] | Unset = UNSET
        if _crosswalk is not UNSET:
            crosswalk = []
            for crosswalk_item_data in _crosswalk:
                crosswalk_item = ContextEvaluateRequestCrosswalkItem.from_dict(crosswalk_item_data)

                crosswalk.append(crosswalk_item)

        context_evaluate_request = cls(
            org_id=org_id,
            design_rows=design_rows,
            settings=settings,
            crosswalk=crosswalk,
        )

        context_evaluate_request.additional_properties = d
        return context_evaluate_request

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
